//! Python-written JSON from the host goldens (`tests/fixtures/host-golden/`, recorded by the
//! Python installer and agent) is read and written back byte-identical by the Rust writers.

use std::fs;
use std::path::{Path, PathBuf};

use pc_host::json::{canonical, canonical_digest, loads, pretty2, pretty2_ascii_nonl};
use serde_json::Value;

fn golden_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/host-golden")
}

fn json_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            json_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "json") {
            out.push(path);
        }
    }
}

fn relative(path: &Path) -> String {
    path.strip_prefix(golden_root()).unwrap().to_string_lossy().into_owned()
}

/// Which host writer produced a golden file, by where the Python code wrote it.
fn designated_writer(rel: &str) -> Option<&'static str> {
    let name = rel.rsplit('/').next().unwrap();
    let in_journal = rel.contains("/journal/") || rel.starts_with("journals/");
    if in_journal && matches!(name, "state.json" | "ownership.json" | "report.json") {
        return Some("pretty2");
    }
    if in_journal && name == "plan.json" {
        return Some("canonical");
    }
    if rel.starts_with("plans/") && name == "plan.json" {
        return Some("canonical");
    }
    if rel.starts_with("agent/updates/") && !rel.starts_with("agent/updates/00-seed/") && name == "state.json" {
        // Written by the agent after an upstream check or an update.
        return Some("pretty2_ascii_nonl");
    }
    if rel == "agent/seed/state.json"
        || rel == "agent/updates/00-seed/state.json"
        || rel.ends_with("var/lib/proxy-control/version-agent/state.json")
    {
        // The installer's seed: indent 2, sorted, ASCII, trailing newline (C1.8).
        return Some("pretty2_ascii");
    }
    None
}

fn render(writer: &str, value: &Value) -> String {
    match writer {
        "pretty2" => pretty2(value),
        "pretty2_ascii" => pc_host::json::pretty2_ascii(value),
        "canonical" => canonical(value),
        "pretty2_ascii_nonl" => pretty2_ascii_nonl(value),
        other => panic!("unknown writer {other}"),
    }
}

#[test]
fn every_host_written_golden_round_trips_byte_identical() {
    let mut files = Vec::new();
    json_files(&golden_root(), &mut files);
    assert!(files.len() > 300, "goldens are present ({} JSON files)", files.len());
    let mut designated = 0;
    let mut by_writer = std::collections::BTreeMap::<&str, usize>::new();
    let mut unmatched = Vec::new();
    for path in &files {
        let rel = relative(path);
        let bytes = fs::read(path).unwrap();
        let value = loads(&bytes).unwrap_or_else(|e| panic!("{rel}: {e}"));
        if let Some(writer) = designated_writer(&rel) {
            designated += 1;
            assert_eq!(render(writer, &value).as_bytes(), &bytes[..], "{rel} is not {writer}");
        }
        let hit = ["pretty2", "canonical", "pretty2_ascii_nonl", "pretty2_ascii"]
            .into_iter()
            .find(|w| render(w, &value).as_bytes() == bytes);
        match hit {
            Some(writer) => *by_writer.entry(writer).or_default() += 1,
            None => unmatched.push(rel),
        }
    }
    eprintln!("designated host files: {designated}; byte-identical by writer: {by_writer:?}");
    assert!(designated >= 60, "{designated}");
    // The rest are not host-sorted formats: Python dicts in insertion order (`versions.json`
    // catalog seed, 3x-ui `config.json`, the Mieru bootstrap input) and CLI stdout with the
    // default separators. They belong to the adapters that render them.
    for rel in &unmatched {
        let name = rel.rsplit('/').next().unwrap();
        assert!(
            matches!(name, "versions.json" | "stdout.json" | "config.json" | "bootstrap-input.json"),
            "unexpected non-host JSON form: {rel}"
        );
    }
}

#[test]
fn plan_digests_are_reproduced_from_the_canonical_bytes() {
    let mut checked = 0;
    for entry in fs::read_dir(golden_root().join("plans")).unwrap() {
        let dir = entry.unwrap().path();
        let (plan, digest) = (dir.join("plan.json"), dir.join("digest"));
        if !plan.exists() {
            continue;
        }
        let bytes = fs::read(&plan).unwrap();
        let value = loads(&bytes).unwrap();
        let expected = fs::read_to_string(&digest).unwrap();
        assert_eq!(canonical_digest(&value), expected.trim(), "{}", dir.display());
        assert_eq!(pc_host::fs::sha256_hex(&bytes), expected.trim());
        checked += 1;
    }
    assert!(checked >= 10, "{checked}");
}

#[test]
fn journal_state_digests_match_their_plans() {
    // `state.plan_digest` is the sha256 of the re-rendered persisted plan (`_read_matching_plan`).
    let mut checked = 0;
    let mut files = Vec::new();
    json_files(&golden_root(), &mut files);
    for state in files.iter().filter(|p| p.ends_with("state.json") && p.parent().unwrap().join("plan.json").exists()) {
        let value = loads(&fs::read(state).unwrap()).unwrap();
        let Some(digest) = value.get("plan_digest").and_then(Value::as_str) else { continue };
        let plan = loads(&fs::read(state.parent().unwrap().join("plan.json")).unwrap()).unwrap();
        assert_eq!(canonical_digest(&plan), digest, "{}", relative(state));
        checked += 1;
    }
    assert!(checked >= 10, "{checked}");
}

#[test]
fn json_vectors_from_python() {
    let root = golden_root().join("vectors");
    let strings = loads(&fs::read(root.join("json-strings.json")).unwrap()).unwrap();
    let mut count = 0;
    for case in strings.as_array().unwrap() {
        let text: String = case["codepoints"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| char::from_u32(u32::from_str_radix(&c.as_str().unwrap()[2..], 16).unwrap()).unwrap())
            .collect();
        let value = Value::String(text);
        assert_eq!(canonical(&value), case["ensure_ascii_false"].as_str().unwrap());
        assert_eq!(pretty2_ascii_nonl(&value), case["ensure_ascii_true"].as_str().unwrap());
        count += 1;
    }
    assert!(count > 5);

    let order = loads(&fs::read(root.join("json-key-order.json")).unwrap()).unwrap();
    let object: serde_json::Map<String, Value> =
        order["keys"].as_array().unwrap().iter().map(|k| (k.as_str().unwrap().to_string(), Value::from(1))).collect();
    let object = Value::Object(object);
    assert_eq!(canonical(&object), order["compact_sorted"].as_str().unwrap());
    assert_eq!(pretty2(&object), format!("{}\n", order["indent2_sorted"].as_str().unwrap()));
    assert_eq!(pretty2_ascii_nonl(&object), order["indent2_sorted_ascii"].as_str().unwrap());
    let empties = serde_json::json!({"a": {}, "b": [], "c": [{}], "d": [[]]});
    assert_eq!(pretty2(&empties), format!("{}\n", order["empty_containers_indent2"].as_str().unwrap()));

    let floats = loads(&fs::read(root.join("float-repr.json")).unwrap()).unwrap();
    let mut count = 0;
    for case in floats.as_array().unwrap() {
        let value = parse_hex_float(case["hex"].as_str().unwrap());
        assert_eq!(pc_host::json::float_repr(value), case["repr"].as_str().unwrap(), "{case}");
        if value.is_finite() {
            assert_eq!(canonical(&serde_json::json!(value)), case["json"].as_str().unwrap(), "{case}");
        }
        count += 1;
    }
    assert!(count > 5);
}

/// `float.hex()` back to a float: `[-]0x1.<13 hex>p<exp>` (and the zero / subnormal forms).
fn parse_hex_float(text: &str) -> f64 {
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
    let (lead, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    // The significand as an integer of `4 * len(fraction)` fraction bits, then exact scaling.
    let mut significand = u64::from_str_radix(lead, 16).unwrap();
    for digit in fraction.chars() {
        significand = significand * 16 + digit.to_digit(16).unwrap() as u64;
    }
    let mut exponent: i32 = exponent.parse::<i32>().unwrap() - 4 * fraction.len() as i32;
    let mut result = significand as f64;
    while exponent > 1000 {
        result *= 2f64.powi(1000);
        exponent -= 1000;
    }
    while exponent < -1000 {
        result *= 2f64.powi(-1000);
        exponent += 1000;
    }
    let result = result * 2f64.powi(exponent);
    if negative {
        -result
    } else {
        result
    }
}
