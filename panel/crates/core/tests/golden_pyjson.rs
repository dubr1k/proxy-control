//! `pyjson` against what Python 3.13.5's `json.dumps` and pydantic-core wrote for the same values
//! (`fixtures/pyjson.json`, made by `fixtures/generators/gen_pyjson.py` in the panel image).

use panel_core::pyjson::{self, Options};
use serde_json::Value;

fn fixture() -> Value {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/pyjson.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn options(spec: &Value) -> Options {
    let mut options = Options::default();
    if let Some(indent) = spec.get("indent") {
        options.indent = Some(indent.as_u64().unwrap() as usize);
    }
    if let Some(separators) = spec.get("separators") {
        let item = separators[0].as_str().unwrap();
        let key = separators[1].as_str().unwrap();
        let leak = |text: &str| -> &'static str { Box::leak(text.to_string().into_boxed_str()) };
        options.separators = Some((leak(item), leak(key)));
    }
    if let Some(sort) = spec.get("sort_keys") {
        options.sort_keys = sort.as_bool().unwrap();
    }
    if let Some(ascii) = spec.get("ensure_ascii") {
        options.ensure_ascii = ascii.as_bool().unwrap();
    }
    options
}

#[test]
fn floats_are_written_like_python_repr_and_pydantic() {
    let fixture = fixture();
    let floats = fixture["floats"].as_array().unwrap();
    assert!(floats.len() > 1900);
    let mut wrong = Vec::new();
    for entry in floats {
        let python = entry[0].as_str().unwrap();
        let pydantic = entry[1].as_str().unwrap();
        let value: f64 = python.parse().unwrap();
        let ours =
            (pyjson::float_repr(value), pyjson::dumps_default(&Value::from(value)), pyjson::pydantic_float(value));
        if ours != (python.to_string(), python.to_string(), pydantic.to_string()) {
            wrong.push(format!("{value:e}: python {python} / {pydantic}, ours {ours:?}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} floats differ: {:#?}",
        wrong.len(),
        floats.len(),
        &wrong[..wrong.len().min(20)]
    );
}

#[test]
fn strings_are_escaped_like_python() {
    let fixture = fixture();
    let strings = fixture["strings"].as_array().unwrap();
    assert!(strings.len() > 400);
    for entry in strings {
        let value = entry[0].clone();
        assert_eq!(pyjson::dumps_default(&value), entry[1].as_str().unwrap(), "ascii {value:?}");
        assert_eq!(pyjson::compact_utf8(&value), entry[2].as_str().unwrap(), "utf-8 {value:?}");
        assert_eq!(pyjson::pydantic(&value), entry[3].as_str().unwrap(), "pydantic {value:?}");
    }
}

#[test]
fn structures_match_every_variant() {
    let fixture = fixture();
    let variants = fixture["variants"].as_object().unwrap();
    let structures = fixture["structures"].as_array().unwrap();
    assert!(structures.len() > 150);
    let mut checked = 0;
    for entry in structures {
        let value: Value = serde_json::from_str(entry["input"].as_str().unwrap()).unwrap();
        for (name, spec) in variants {
            let expected = entry["out"][name].as_str().unwrap();
            assert_eq!(pyjson::dumps(&value, &options(spec)), expected, "variant {name} of {}", entry["input"]);
            checked += 1;
        }
        assert_eq!(pyjson::pydantic(&value), entry["pydantic"].as_str().unwrap(), "pydantic {}", entry["input"]);
    }
    assert!(checked > 1500);
}

#[test]
fn named_shortcuts_are_the_python_variants() {
    let value: Value = serde_json::from_str(r#"{"b": [1, 1e-05, "é"], "a": {}}"#).unwrap();
    assert_eq!(pyjson::compact(&value), r#"{"b":[1,1e-05,"\u00e9"],"a":{}}"#);
    assert_eq!(pyjson::canonical(&value), r#"{"a":{},"b":[1,1e-05,"\u00e9"]}"#);
    assert_eq!(pyjson::sorted(&value), r#"{"a": {}, "b": [1, 1e-05, "\u00e9"]}"#);
    assert_eq!(pyjson::compact_utf8(&value), "{\"b\":[1,1e-05,\"é\"],\"a\":{}}");
    assert_eq!(pyjson::pydantic(&value), "{\"b\":[1,0.00001,\"é\"],\"a\":{}}");
}
