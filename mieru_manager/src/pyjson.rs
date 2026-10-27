//! Python's `json.dumps`, truthiness, `str()` and `==` over JSON values.
//!
//! Every revision, config hash and journal MAC of the manager is a SHA-256 over
//! `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`, and the state
//! files are that text plus a newline, so the bytes must be Python's exactly: sorted keys,
//! `\uXXXX` for everything outside printable ASCII (surrogate pairs above the BMP), and floats
//! as `repr` prints them (`1e+16`, `1.5e-05`).

use serde_json::Value;

/// `json.dumps(value, sort_keys=sort_keys, ensure_ascii=True, …)`: with `indent`, Python's
/// pretty layout (`", "`-free item separator, `": "` between key and value); without, the
/// compact `(",", ":")` separators.
pub fn dumps(value: &Value, sort_keys: bool, indent: Option<usize>) -> String {
    let mut out = String::new();
    write_value(&mut out, value, sort_keys, indent, 0);
    out
}

/// The manager's canonical form: compact, sorted, ASCII.
pub fn canonical(value: &Value) -> String {
    dumps(value, true, None)
}

fn newline(out: &mut String, indent: Option<usize>, level: usize) {
    if let Some(width) = indent {
        out.push('\n');
        out.extend(std::iter::repeat_n(' ', width * level));
    }
}

fn write_value(out: &mut String, value: &Value, sort_keys: bool, indent: Option<usize>, level: usize) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => out.push_str(&number_text(number)),
        Value::String(text) => write_string(out, text),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(out, indent, level + 1);
                write_value(out, item, sort_keys, indent, level + 1);
            }
            newline(out, indent, level);
            out.push(']');
        }
        Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            if sort_keys {
                // Python compares str by code point; UTF-8 byte order is the same order.
                entries.sort_by(|a, b| a.0.cmp(b.0));
            }
            out.push('{');
            for (i, (key, item)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(out, indent, level + 1);
                write_string(out, key);
                out.push_str(if indent.is_some() { ": " } else { ":" });
                write_value(out, item, sort_keys, indent, level + 1);
            }
            newline(out, indent, level);
            out.push('}');
        }
    }
}

fn write_string(out: &mut String, text: &str) {
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

fn number_text(number: &serde_json::Number) -> String {
    if let Some(n) = number.as_i64() {
        n.to_string()
    } else if let Some(n) = number.as_u64() {
        n.to_string()
    } else {
        float_repr(number.as_f64().unwrap_or(0.0))
    }
}

/// `repr(float)`: the shortest round-trip digits, scientific below 1e-4 and from 1e16 on.
pub fn float_repr(value: f64) -> String {
    if value.is_nan() {
        return "NaN".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    if value == 0.0 {
        return if value.is_sign_negative() { "-0.0".into() } else { "0.0".into() };
    }
    let scientific = format!("{value:e}");
    let (mantissa, exponent) = scientific.split_once('e').unwrap_or((&scientific, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let (sign, mantissa) = match mantissa.strip_prefix('-') {
        Some(rest) => ("-", rest),
        None => ("", mantissa),
    };
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let body = if !(-4..16).contains(&exponent) {
        let mut text = digits[..1].to_string();
        if digits.len() > 1 {
            text.push('.');
            text.push_str(&digits[1..]);
        }
        format!("{text}e{}{:02}", if exponent < 0 { '-' } else { '+' }, exponent.abs())
    } else if exponent >= 0 {
        let whole = exponent as usize + 1;
        if digits.len() <= whole {
            format!("{digits}{}.0", "0".repeat(whole - digits.len()))
        } else {
            format!("{}.{}", &digits[..whole], &digits[whole..])
        }
    } else {
        format!("0.{}{digits}", "0".repeat((-exponent - 1) as usize))
    };
    format!("{sign}{body}")
}

/// An integer as Python sees it: `True` is 1, `1.0` equals 1.
fn as_int(value: &Value) -> Option<i128> {
    match value {
        Value::Bool(b) => Some(i128::from(*b)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(i128::from(i))
            } else if let Some(u) = n.as_u64() {
                Some(i128::from(u))
            } else {
                let f = n.as_f64()?;
                (f.is_finite() && f.fract() == 0.0 && f.abs() < 1e38).then_some(f as i128)
            }
        }
        _ => None,
    }
}

fn is_numeric(value: &Value) -> bool {
    matches!(value, Value::Bool(_) | Value::Number(_))
}

/// Python's `==` between two JSON values: numbers compare by value across int, float and bool;
/// dicts ignore key order.
pub fn eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| eq(p, q)),
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(key, value)| y.get(key).is_some_and(|other| eq(value, other)))
        }
        (x, y) if is_numeric(x) && is_numeric(y) => match (as_int(x), as_int(y)) {
            (Some(p), Some(q)) => p == q,
            (None, None) => x.as_f64() == y.as_f64(),
            _ => false,
        },
        _ => false,
    }
}

/// `value == number` in Python.
pub fn eq_int(value: &Value, number: i64) -> bool {
    is_numeric(value) && as_int(value) == Some(i128::from(number))
}

/// Python's `str(value)` for the values a config holds; containers as their `repr`.
pub fn py_str(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        _ => py_repr(value),
    }
}

fn py_repr(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) => number_text(n),
        Value::String(s) => repr_str(s),
        Value::Array(items) => format!("[{}]", items.iter().map(py_repr).collect::<Vec<_>>().join(", ")),
        Value::Object(map) => format!(
            "{{{}}}",
            map.iter().map(|(k, v)| format!("{}: {}", repr_str(k), py_repr(v))).collect::<Vec<_>>().join(", ")
        ),
    }
}

fn repr_str(text: &str) -> String {
    pc_common::pytext::repr_with_printable(text, |_| true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_common::pytext::strip;
    use pc_common::pyvalue::{strict_int as int_of, truthy};
    use serde_json::json;

    #[test]
    fn floats_print_like_python_repr() {
        for (value, text) in [
            (1.0, "1.0"),
            (1e16, "1e+16"),
            (1.5e-5, "1.5e-05"),
            (0.0001, "0.0001"),
            (1.2345678901234568e17, "1.2345678901234568e+17"),
            (-0.0, "-0.0"),
            (1e22, "1e+22"),
            (2.5, "2.5"),
            (123.456, "123.456"),
            (0.1, "0.1"),
            (9999999999999998.0, "9999999999999998.0"),
            (-3.0e-10, "-3e-10"),
        ] {
            assert_eq!(float_repr(value), text);
        }
    }

    #[test]
    fn python_equality_and_truthiness() {
        assert!(eq(&json!({"a": [1, true]}), &json!({"a": [1.0, 1]})));
        assert!(!eq(&json!({"a": 1}), &json!({"a": "1"})));
        assert!(eq_int(&json!(true), 1) && eq_int(&json!(2.0), 2) && !eq_int(&json!("2"), 2));
        assert!(!truthy(&json!(0)) && !truthy(&json!("")) && !truthy(&json!({})) && truthy(&json!([0])));
        assert_eq!(int_of(&json!(5)), Some(5));
        assert_eq!(int_of(&json!(true)), None);
        assert_eq!(int_of(&json!(5.0)), None);
        assert_eq!(py_str(&json!(8443)), "8443");
        assert_eq!(py_str(&json!("1-2")), "1-2");
        assert_eq!(py_str(&json!(true)), "True");
        assert_eq!(strip("\u{1c} x \n"), "x");
    }
}
