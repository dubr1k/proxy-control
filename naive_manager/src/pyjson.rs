//! `json.dumps` as the Python manager called it, byte for byte: the state file
//! (`indent=2, ensure_ascii=False`), the transaction journal and every API body
//! (`separators=(",", ":")`, ASCII-escaped), the egress document's canonical form
//! (`sort_keys=True`), and the Caddy config sent back to the admin API.
//! Float notation retains the manager's legacy Rust shortest-digit tie rounding.

use pc_common::json::{FloatMode, NumberMode, Options};

/// `json.dumps(value, separators=(",", ":"))`.
pub const COMPACT: Options = Options {
    indent: None,
    separators: Some((",", ":")),
    sort_keys: false,
    ensure_ascii: true,
    numbers: NumberMode::Python(FloatMode::RustShortest),
};
/// `json.dumps(value, ensure_ascii=False, indent=2)`.
pub const STATE: Options = Options { indent: Some(2), separators: None, ensure_ascii: false, ..COMPACT };
/// `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`.
pub const CANONICAL: Options = Options { sort_keys: true, ..COMPACT };

#[cfg(test)]
mod tests {
    use super::*;
    use pc_common::json::{dumps, float_repr};
    use serde_json::{json, Value};

    #[test]
    fn dumps_matches_python_layouts() {
        let value: Value =
            serde_json::from_str(r#"{"b": [1, {"x": null}], "a": "é\u2028\u007f\"\n", "e": {}, "l": []}"#).unwrap();
        assert_eq!(dumps(&value, &COMPACT), r#"{"b":[1,{"x":null}],"a":"\u00e9\u2028\u007f\"\n","e":{},"l":[]}"#);
        assert_eq!(dumps(&value, &CANONICAL), r#"{"a":"\u00e9\u2028\u007f\"\n","b":[1,{"x":null}],"e":{},"l":[]}"#);
        assert_eq!(
            dumps(&value, &STATE),
            "{\n  \"b\": [\n    1,\n    {\n      \"x\": null\n    }\n  ],\n  \"a\": \"é\u{2028}\u{7f}\\\"\\n\",\n  \"e\": {},\n  \"l\": []\n}"
        );
        assert_eq!(dumps(&json!("😀"), &COMPACT), "\"\\ud83d\\ude00\"");
    }

    #[test]
    fn floats_print_like_python_repr() {
        for (value, text) in [
            (1.0, "1.0"),
            (1.5e-05, "1.5e-05"),
            (0.0001, "0.0001"),
            (1e16, "1e+16"),
            (1234567890123456.0, "1234567890123456.0"),
            (-0.5, "-0.5"),
            (1e100, "1e+100"),
            (123.456, "123.456"),
            (0.1, "0.1"),
        ] {
            assert_eq!(float_repr(value, FloatMode::RustShortest), text);
        }
    }
}
