//! `json.dumps` byte for byte: the generation files are hashed into the generation digest, the
//! intents into their revisions, and every state file is read back by an older manager — so the
//! bytes, not just the values, are the contract.
//!
//! Python's encoder: `ensure_ascii=True` (everything outside ' '..'~' as `\uXXXX`, lower-case hex,
//! surrogate pairs above the BMP), `sort_keys` by code point, the separators, `indent`, and floats
//! as `repr()` prints them.

use std::fmt::Write;

use serde_json::{Number, Value};

#[derive(Debug, Clone, Copy)]
pub struct Format {
    pub sort_keys: bool,
    pub indent: Option<usize>,
    pub item_sep: &'static str,
    pub key_sep: &'static str,
}

/// `json.dumps(v, sort_keys=True, separators=(",", ":"))`: generations, state files, digests.
pub const SORTED: Format = Format { sort_keys: true, indent: None, item_sep: ",", key_sep: ":" };
/// `json.dumps(v, separators=(",", ":"))`: the API answers.
pub const COMPACT: Format = Format { sort_keys: false, indent: None, item_sep: ",", key_sep: ":" };
/// `json.dumps(v)`: the WARP registration body.
pub const DEFAULT: Format = Format { sort_keys: false, indent: None, item_sep: ", ", key_sep: ": " };
/// `json.dumps(v, indent=1, sort_keys=True)`: the plan's diff lines.
pub const INDENT1_SORTED: Format = Format { sort_keys: true, indent: Some(1), item_sep: ",", key_sep: ": " };

pub fn dumps(value: &Value, format: &Format) -> String {
    let mut out = String::new();
    write_value(&mut out, value, format, 0);
    out
}

fn newline(out: &mut String, format: &Format, level: usize) {
    if let Some(indent) = format.indent {
        out.push('\n');
        out.extend(std::iter::repeat_n(' ', indent * level));
    }
}

fn write_value(out: &mut String, value: &Value, format: &Format, level: usize) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => out.push_str(&number_repr(number)),
        Value::String(text) => write_str(out, text),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(format.item_sep);
                }
                newline(out, format, level + 1);
                write_value(out, item, format, level + 1);
            }
            newline(out, format, level);
            out.push(']');
        }
        Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            if format.sort_keys {
                entries.sort_by(|a, b| a.0.cmp(b.0));
            }
            out.push('{');
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index > 0 {
                    out.push_str(format.item_sep);
                }
                newline(out, format, level + 1);
                write_str(out, key);
                out.push_str(format.key_sep);
                write_value(out, item, format, level + 1);
            }
            newline(out, format, level);
            out.push('}');
        }
    }
}

fn write_str(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            _ => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
}

fn number_repr(number: &Number) -> String {
    if let Some(n) = number.as_u64() {
        return n.to_string();
    }
    if let Some(n) = number.as_i64() {
        return n.to_string();
    }
    float_repr(number.as_f64().unwrap_or(0.0))
}

/// `repr(float)`: the shortest round-trip digits, positional for exponents -4..16, else
/// `d.ddde±XX`; an integral value keeps its `.0`.
pub fn float_repr(x: f64) -> String {
    if x.is_nan() {
        return "NaN".into();
    }
    if x.is_infinite() {
        return if x > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    let scientific = format!("{x:e}");
    let (mantissa, exponent) = scientific.split_once('e').expect("{:e} always has an exponent");
    let exponent: i32 = exponent.parse().expect("a decimal exponent");
    let (sign, mantissa) = match mantissa.strip_prefix('-') {
        Some(rest) => ("-", rest),
        None => ("", mantissa),
    };
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let point = exponent + 1;
    let body = if point <= -4 || point > 16 {
        let (first, rest) = digits.split_at(1);
        let fraction = if rest.is_empty() { String::new() } else { format!(".{rest}") };
        let exp_sign = if exponent < 0 { '-' } else { '+' };
        format!("{first}{fraction}e{exp_sign}{:02}", exponent.abs())
    } else if point <= 0 {
        format!("0.{}{digits}", "0".repeat((-point) as usize))
    } else if point as usize >= digits.len() {
        format!("{digits}{}.0", "0".repeat(point as usize - digits.len()))
    } else {
        let (whole, fraction) = digits.split_at(point as usize);
        format!("{whole}.{fraction}")
    };
    format!("{sign}{body}")
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(float_repr(1e16), "1e+16");
        assert_eq!(float_repr(1.5e-7), "1.5e-07");
        assert_eq!(float_repr(0.0001), "0.0001");
        assert_eq!(float_repr(-0.0), "-0.0");
        assert_eq!(float_repr(1_790_000_000.0), "1790000000.0");
        assert_eq!(float_repr(1234567890123456.0), "1234567890123456.0");
    }
}
