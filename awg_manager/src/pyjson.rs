//! JSON text exactly as Python's `json.dumps` writes it (ASCII-only, `\uXXXX` escapes), so the
//! state file, the request digests and the plan's diff stay byte-identical with the Python manager.

use pc_common::json::{dumps, NumberMode, Options};
use serde_json::Value;

/// `json.dumps(value, indent=1, sort_keys=True)`: the state file.
pub fn state(value: &Value) -> String {
    dumps(value, &Options { indent: Some(1), separators: None, ..CANONICAL })
}

/// `json.dumps(value, sort_keys=True, separators=(",", ":"))`: digests.
pub fn canonical(value: &Value) -> String {
    dumps(value, &CANONICAL)
}

/// `json.dumps(value)`: insertion order, `", "` and `": "`.
pub fn plain(value: &Value) -> String {
    dumps(value, &Options { sort_keys: false, separators: None, ..CANONICAL })
}

const CANONICAL: Options = Options {
    indent: None,
    sort_keys: true,
    separators: Some((",", ":")),
    ensure_ascii: true,
    // AWG historically uses serde's number display, not Python float notation.
    numbers: NumberMode::Serde,
};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn layouts_match_python() {
        let value = json!({"schema": 1, "upstream": {"provider": "warp"}, "a": [], "b": {}, "c": [1, null]});
        assert_eq!(
            state(&value),
            "{\n \"a\": [],\n \"b\": {},\n \"c\": [\n  1,\n  null\n ],\n \"schema\": 1,\n \"upstream\": {\n  \"provider\": \"warp\"\n }\n}"
        );
        assert_eq!(canonical(&value), r#"{"a":[],"b":{},"c":[1,null],"schema":1,"upstream":{"provider":"warp"}}"#);
        assert_eq!(plain(&json!({"z": "", "a": true})), r#"{"z": "", "a": true}"#);
    }

    #[test]
    fn strings_are_ascii_escaped() {
        assert_eq!(canonical(&json!("\u{438}\u{7f}\"\\\u{1}\u{1f600}")), r#""\u0438\u007f\"\\\u0001\ud83d\ude00""#);
    }
}
