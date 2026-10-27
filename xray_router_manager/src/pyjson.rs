//! `json.dumps` byte for byte: the generation files are hashed into the generation digest, the
//! intents into their revisions, and every state file is read back by an older manager — so the
//! bytes, not just the values, are the contract.
//!
//! Python's encoder: `ensure_ascii=True` (everything outside ' '..'~' as `\uXXXX`, lower-case hex,
//! surrogate pairs above the BMP), `sort_keys` by code point, the separators, `indent`, and floats
//! as `repr()` prints them.
//! Exact shortest-digit ties retain the legacy manager's Rust rounding, not the host's
//! Python tie-even correction; the shared options below make that byte contract explicit.

use pc_common::json::{FloatMode, NumberMode, Options};

/// `json.dumps(v, sort_keys=True, separators=(",", ":"))`: generations, state files, digests.
pub const SORTED: Options = Options {
    sort_keys: true,
    indent: None,
    separators: Some((",", ":")),
    ensure_ascii: true,
    numbers: NumberMode::Python(FloatMode::RustShortest),
};
/// `json.dumps(v, separators=(",", ":"))`: the API answers.
pub const COMPACT: Options = Options { sort_keys: false, ..SORTED };
/// `json.dumps(v)`: the WARP registration body.
pub const DEFAULT: Options = Options { separators: None, ..COMPACT };
/// `json.dumps(v, indent=1, sort_keys=True)`: the plan's diff lines.
pub const INDENT1_SORTED: Options = Options { indent: Some(1), separators: None, ..SORTED };

#[cfg(test)]
mod tests {
    use super::*;
    use pc_common::json::{dumps, float_repr};
    use serde_json::Value;

    const GOLDEN: &str = include_str!("../testdata/pyjson.json");

    #[test]
    fn floats_strings_and_layouts_match_python() {
        let golden: Value = serde_json::from_str(GOLDEN).unwrap();
        let json = &golden["json"];
        let floats: Vec<f64> = serde_json::from_str::<Vec<f64>>(json["floats"].as_str().unwrap()).unwrap();
        let as_values = Value::Array(floats.iter().map(|f| Value::from(*f)).collect());
        assert_eq!(dumps(&as_values, &DEFAULT), json["floats"].as_str().unwrap());
        assert_eq!(dumps(&as_values, &COMPACT), json["floats_compact"].as_str().unwrap());
        let strings: Value = serde_json::from_str(json["strings"].as_str().unwrap()).unwrap();
        assert_eq!(dumps(&strings, &DEFAULT), json["strings"].as_str().unwrap());
        assert_eq!(dumps(&json["nested"], &INDENT1_SORTED), json["nested_indent"].as_str().unwrap());
    }

    #[test]
    fn float_repr_edges() {
        assert_eq!(float_repr(1e16, FloatMode::RustShortest), "1e+16");
        assert_eq!(float_repr(1.5e-7, FloatMode::RustShortest), "1.5e-07");
        assert_eq!(float_repr(0.0001, FloatMode::RustShortest), "0.0001");
        assert_eq!(float_repr(-0.0, FloatMode::RustShortest), "-0.0");
        assert_eq!(float_repr(1_790_000_000.0, FloatMode::RustShortest), "1790000000.0");
        assert_eq!(float_repr(1234567890123456.0, FloatMode::RustShortest), "1234567890123456.0");
    }
}
