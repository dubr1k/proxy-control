//! JSON text exactly as Python's `json.dumps` writes it (ASCII-only, `\uXXXX` escapes), so the
//! state file, the request digests and the plan's diff stay byte-identical with the Python manager.

use serde_json::Value;

struct Style {
    indent: Option<usize>,
    sort_keys: bool,
    item_sep: &'static str,
    key_sep: &'static str,
}

/// `json.dumps(value, indent=1, sort_keys=True)`: the state file.
pub fn state(value: &Value) -> String {
    dumps(value, &Style { indent: Some(1), sort_keys: true, item_sep: ",", key_sep: ": " })
}

/// `json.dumps(value, sort_keys=True, separators=(",", ":"))`: digests.
pub fn canonical(value: &Value) -> String {
    dumps(value, &Style { indent: None, sort_keys: true, item_sep: ",", key_sep: ":" })
}

/// `json.dumps(value)`: insertion order, `", "` and `": "`.
pub fn plain(value: &Value) -> String {
    dumps(value, &Style { indent: None, sort_keys: false, item_sep: ", ", key_sep: ": " })
}

fn dumps(value: &Value, style: &Style) -> String {
    let mut out = String::new();
    write(&mut out, value, style, 0);
    out
}

fn newline(out: &mut String, style: &Style, level: usize) {
    if let Some(indent) = style.indent {
        out.push('\n');
        out.extend(std::iter::repeat_n(' ', indent * level));
    }
}

fn write(out: &mut String, value: &Value, style: &Style, level: usize) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::String(text) => escape(out, text),
        Value::Array(items) if items.is_empty() => out.push_str("[]"),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(style.item_sep);
                }
                newline(out, style, level + 1);
                write(out, item, style, level + 1);
            }
            newline(out, style, level);
            out.push(']');
        }
        Value::Object(map) if map.is_empty() => out.push_str("{}"),
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            if style.sort_keys {
                // Rust orders strings by UTF-8 bytes, which is code-point order, as Python does.
                entries.sort_by(|a, b| a.0.cmp(b.0));
            }
            out.push('{');
            for (i, (key, item)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push_str(style.item_sep);
                }
                newline(out, style, level + 1);
                escape(out, key);
                out.push_str(style.key_sep);
                write(out, item, style, level + 1);
            }
            newline(out, style, level);
            out.push('}');
        }
    }
}

/// `ensure_ascii=True`: printable ASCII as is, everything else escaped (lowercase hex).
fn escape(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(ch),
            _ => {
                let mut units = [0u16; 2];
                for unit in ch.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
}

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
