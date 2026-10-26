//! Python semantics the configuration and the digest rely on (`tests/fixtures/host-golden/
//! vectors/`, recorded from Python 3.12): domain validation, `ipaddress`, `str.strip/split/
//! isspace/lower`, `str()` of scalars, JSON string escaping, key and set order, float `repr`.
//! `validators-version`, `compare-versions` and `round` belong to the wizard and the agent.

use std::path::{Path, PathBuf};

use installer_core::config::normalize_domain;
use installer_core::ipaddr::{ip_address, ipv4_address, ipv6_address};
use installer_core::planner::Fact;
use installer_core::pystr::{is_space, lower, split_whitespace, strip};
use serde_json::Value;

fn vectors() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/host-golden/vectors")
}

fn load(name: &str) -> Vec<Value> {
    let value: Value = serde_json::from_slice(&std::fs::read(vectors().join(name)).unwrap()).unwrap();
    match value {
        Value::Array(items) => items,
        other => vec![other],
    }
}

fn codepoint(text: &str) -> char {
    char::from_u32(u32::from_str_radix(text.trim_start_matches("U+"), 16).unwrap()).unwrap()
}

#[test]
fn domains_validate_like_the_config_validator() {
    let mut checked = 0;
    for case in load("validators-domain.json") {
        let input = case["input"].as_str().unwrap();
        let outcome = &case["config_domain"];
        let ours = normalize_domain(input);
        if input == "a.example.c0m" {
            // Deliberate: a digit in the top-level label is refused (DIFFERENCES.md).
            assert_eq!(ours, None);
        } else if let Some(ok) = outcome.get("ok") {
            assert_eq!(ours.as_deref(), ok.as_str(), "{input:?}");
        } else {
            assert_eq!(outcome["message"], "invalid domain: domains.panel");
            assert_eq!(ours, None, "{input:?}");
        }
        checked += 1;
    }
    assert!(checked >= 25);
}

#[test]
fn ipaddress_matches_python() {
    for case in load("ipaddress.json") {
        let input = case["input"].as_str().unwrap();
        for (column, ours) in [
            ("IPv4Address", ipv4_address(input)),
            ("IPv6Address", ipv6_address(input)),
            ("ip_address", ip_address(input)),
        ] {
            let expected = &case[column];
            match (expected.get("ok"), ours) {
                (Some(ok), Ok(value)) => assert_eq!(ok.as_str(), Some(value.as_str()), "{column}({input:?})"),
                (None, Err(message)) => {
                    assert_eq!(expected["message"].as_str(), Some(message.as_str()), "{column}({input:?})")
                }
                (expected, ours) => panic!("{column}({input:?}): python {expected:?}, rust {ours:?}"),
            }
        }
    }
}

#[test]
fn whitespace_matches_python() {
    for case in load("str-strip.json") {
        let input = case["input"].as_str().unwrap();
        assert_eq!(strip(input), case["strip"].as_str().unwrap(), "{input:?}");
        let split: Vec<&str> = case["split"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(split_whitespace(input), split, "{input:?}");
        let codepoints: Vec<char> =
            case["codepoints"].as_array().unwrap().iter().map(|v| codepoint(v.as_str().unwrap())).collect();
        let spaces: Vec<bool> = case["isspace"].as_array().unwrap().iter().map(|v| v.as_bool().unwrap()).collect();
        assert_eq!(codepoints.iter().map(|c| is_space(*c)).collect::<Vec<_>>(), spaces, "{input:?}");
    }
}

#[test]
fn lowercasing_matches_python() {
    for case in load("str-lower.json") {
        let input = case["input"].as_str().unwrap();
        assert_eq!(lower(input), case["lower"].as_str().unwrap(), "{input:?}");
        let normalised = lower(strip(input)).trim_end_matches('.').to_string();
        assert_eq!(normalised, case["normalised_domain"].as_str().unwrap(), "{input:?}");
    }
}

#[test]
fn str_of_scalars_matches_python() {
    let cases = load("str-of-scalars.json");
    let find = |python: &str| cases.iter().find(|c| c["python"] == python).unwrap()["value"].clone();
    let py_str = pc_host::archive::identity::py_str;
    assert_eq!(py_str(&serde_json::json!(true)).unwrap(), find("str(True)"));
    assert_eq!(py_str(&serde_json::json!(false)).unwrap(), find("str(False)"));
    assert_eq!(py_str(&Value::Null).unwrap(), find("str(None)"));
    assert_eq!(py_str(&serde_json::json!(443)).unwrap(), find("str(443)"));
    assert_eq!(py_str(&serde_json::json!(-1)).unwrap(), find("str(-1)"));
    assert_eq!(py_str(&serde_json::json!(1.0)).unwrap(), find("str(1.0)"));
    assert_eq!(py_str(&serde_json::json!(1e16)).unwrap(), find("str(1e16)"));
    assert_eq!(py_str(&serde_json::json!(0.1 + 0.2)).unwrap(), find("str(0.1+0.2)"));
}

#[test]
fn json_strings_and_order_match_python() {
    for case in load("json-strings.json") {
        let text: String =
            case["codepoints"].as_array().unwrap().iter().map(|v| codepoint(v.as_str().unwrap())).collect();
        let value = Value::String(text);
        assert_eq!(pc_host::json::canonical(&value), case["ensure_ascii_false"].as_str().unwrap());
        let ascii = pc_host::json::Options { indent: None, separators: None, sort_keys: true, ensure_ascii: true };
        assert_eq!(pc_host::json::dumps(&value, &ascii), case["ensure_ascii_true"].as_str().unwrap());
    }
    let order = &load("json-key-order.json")[0];
    let mut object = serde_json::Map::new();
    for key in order["keys"].as_array().unwrap() {
        object.insert(key.as_str().unwrap().to_string(), serde_json::json!(1));
    }
    let object = Value::Object(object);
    assert_eq!(pc_host::json::canonical(&object), order["compact_sorted"].as_str().unwrap());
    assert_eq!(
        pc_host::json::dumps(&object, &pc_host::json::Options::PRETTY2),
        order["indent2_sorted"].as_str().unwrap()
    );
    let set = Fact::Set(vec![
        Fact::Bool(true),
        Fact::Str("9".into()),
        Fact::Int(100),
        Fact::Null,
        Fact::List(vec![Fact::Int(1)]),
        Fact::Int(9),
        Fact::Map([("a".to_string(), Fact::Int(1))].into_iter().collect()),
        Fact::Str("10".into()),
        Fact::Int(10),
    ]);
    let ordered: Vec<String> = match set.canonical().unwrap() {
        Value::Array(items) => items
            .iter()
            .map(|item| {
                pc_host::json::dumps(
                    item,
                    &pc_host::json::Options { indent: None, separators: None, sort_keys: true, ensure_ascii: false },
                )
            })
            .collect(),
        _ => unreachable!(),
    };
    let expected: Vec<String> = order["set_order_by_compact_json"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(ordered, expected);
}

/// `float.fromhex` for the canonical forms `float.hex()` writes.
fn from_hex(text: &str) -> f64 {
    match text {
        "inf" => return f64::INFINITY,
        "-inf" => return f64::NEG_INFINITY,
        "nan" => return f64::NAN,
        _ => {}
    }
    let (negative, rest) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let rest = rest.strip_prefix("0x").unwrap();
    let (mantissa, exponent) = rest.split_once('p').unwrap();
    let (lead, fraction) = mantissa.split_once('.').unwrap_or((mantissa, "0"));
    let fraction_bits = u64::from_str_radix(&format!("{fraction:0<13}"), 16).unwrap();
    let exponent: i64 = exponent.parse().unwrap();
    let bits = if lead == "0" { fraction_bits } else { (((exponent + 1023) as u64) << 52) | fraction_bits };
    let value = f64::from_bits(bits);
    if negative {
        -value
    } else {
        value
    }
}

#[test]
fn float_repr_matches_python() {
    for case in load("float-repr.json") {
        let value = from_hex(case["hex"].as_str().unwrap());
        assert_eq!(pc_host::json::float_repr(value), case["repr"].as_str().unwrap(), "{}", case["hex"]);
    }
}
