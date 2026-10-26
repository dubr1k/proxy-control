//! `json.dumps` as the Python manager called it, byte for byte: the state file
//! (`indent=2, ensure_ascii=False`), the transaction journal and every API body
//! (`separators=(",", ":")`, ASCII-escaped), the egress document's canonical form
//! (`sort_keys=True`), and the Caddy config sent back to the admin API.

use serde_json::Value;

#[derive(Debug, Clone, Copy)]
pub struct Options {
    pub indent: Option<usize>,
    pub sort_keys: bool,
    pub ensure_ascii: bool,
}

/// `json.dumps(value, separators=(",", ":"))`.
pub const COMPACT: Options = Options { indent: None, sort_keys: false, ensure_ascii: true };
/// `json.dumps(value, ensure_ascii=False, indent=2)`.
pub const STATE: Options = Options { indent: Some(2), sort_keys: false, ensure_ascii: false };
/// `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`.
pub const CANONICAL: Options = Options { indent: None, sort_keys: true, ensure_ascii: true };

pub fn dumps(value: &Value, options: Options) -> String {
    let mut out = String::new();
    write_value(&mut out, value, options, 0);
    out
}

fn newline(out: &mut String, options: Options, level: usize) {
    if let Some(indent) = options.indent {
        out.push('\n');
        out.extend(std::iter::repeat_n(' ', indent * level));
    }
}

fn write_value(out: &mut String, value: &Value, options: Options, level: usize) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => match (number.as_i64(), number.as_u64(), number.as_f64()) {
            (Some(i), _, _) => out.push_str(&i.to_string()),
            (None, Some(u), _) => out.push_str(&u.to_string()),
            (None, None, Some(f)) => out.push_str(&float_repr(f)),
            _ => out.push_str(&number.to_string()),
        },
        Value::String(text) => write_string(out, text, options.ensure_ascii),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                newline(out, options, level + 1);
                write_value(out, item, options, level + 1);
            }
            newline(out, options, level);
            out.push(']');
        }
        Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            if options.sort_keys {
                entries.sort_by(|a, b| a.0.cmp(b.0));
            }
            out.push('{');
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                newline(out, options, level + 1);
                write_string(out, key, options.ensure_ascii);
                out.push_str(if options.indent.is_some() { ": " } else { ":" });
                write_value(out, item, options, level + 1);
            }
            newline(out, options, level);
            out.push('}');
        }
    }
}

fn write_string(out: &mut String, text: &str, ensure_ascii: bool) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if ensure_ascii && !(' '..='~').contains(&c) => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `repr(float)`: the shortest round-trip digits, positional between 1e-4 and 1e16.
pub fn float_repr(value: f64) -> String {
    if value.is_nan() {
        return "NaN".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    let sign = if value.is_sign_negative() { "-" } else { "" };
    let scientific = format!("{:e}", value.abs());
    let (mantissa, exponent) = scientific.split_once('e').unwrap_or((&scientific, "0"));
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let point = exponent + 1;
    if -4 < point && point <= 16 {
        let body = if point <= 0 {
            format!("0.{}{}", "0".repeat((-point) as usize), digits)
        } else if point as usize >= digits.len() {
            format!("{}{}.0", digits, "0".repeat(point as usize - digits.len()))
        } else {
            format!("{}.{}", &digits[..point as usize], &digits[point as usize..])
        };
        return format!("{sign}{body}");
    }
    let tail = if digits.len() > 1 { format!(".{}", &digits[1..]) } else { String::new() };
    let exp_sign = if exponent < 0 { '-' } else { '+' };
    format!("{sign}{}{tail}e{exp_sign}{:02}", &digits[..1], exponent.abs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dumps_matches_python_layouts() {
        let value: Value =
            serde_json::from_str(r#"{"b": [1, {"x": null}], "a": "é\u2028\u007f\"\n", "e": {}, "l": []}"#).unwrap();
        assert_eq!(dumps(&value, COMPACT), r#"{"b":[1,{"x":null}],"a":"\u00e9\u2028\u007f\"\n","e":{},"l":[]}"#);
        assert_eq!(dumps(&value, CANONICAL), r#"{"a":"\u00e9\u2028\u007f\"\n","b":[1,{"x":null}],"e":{},"l":[]}"#);
        assert_eq!(
            dumps(&value, STATE),
            "{\n  \"b\": [\n    1,\n    {\n      \"x\": null\n    }\n  ],\n  \"a\": \"é\u{2028}\u{7f}\\\"\\n\",\n  \"e\": {},\n  \"l\": []\n}"
        );
        assert_eq!(dumps(&json!("😀"), COMPACT), "\"\\ud83d\\ude00\"");
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
            assert_eq!(float_repr(value), text);
        }
    }
}
