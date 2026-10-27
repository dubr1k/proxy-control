//! Python's `json.dumps`, truthiness, `str()` and `==` over JSON values.
//!
//! Every revision, config hash and journal MAC of the manager is a SHA-256 over
//! `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`, and the state
//! files are that text plus a newline, so the bytes must be Python's exactly: sorted keys,
//! `\uXXXX` for everything outside printable ASCII (surrogate pairs above the BMP), and floats
//! as `repr` prints them (`1e+16`, `1.5e-05`).
//! The historical manager float formatter keeps Rust's shortest digits on an exact tie;
//! shared formatting selects that mode explicitly rather than changing existing hashes.

use pc_common::json::{self, FloatMode, NumberMode, Options};
use serde_json::Value;

/// `json.dumps(value, sort_keys=sort_keys, ensure_ascii=True, …)`: with `indent`, Python's
/// pretty layout (`", "`-free item separator, `": "` between key and value); without, the
/// compact `(",", ":")` separators.
pub fn dumps(value: &Value, sort_keys: bool, indent: Option<usize>) -> String {
    json::dumps(
        value,
        &Options {
            indent,
            separators: if indent.is_some() { None } else { Some((",", ":")) },
            sort_keys,
            ensure_ascii: true,
            numbers: NumberMode::Python(FloatMode::RustShortest),
        },
    )
}

/// The manager's canonical form: compact, sorted, ASCII.
pub fn canonical(value: &Value) -> String {
    dumps(value, true, None)
}

/// Python's `bool(value)`.
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
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

/// A Python `int` (not a `bool`, not a float), as `isinstance(value, int) and not
/// isinstance(value, bool)` accepts it.
pub fn int_of(value: &Value) -> Option<i128> {
    match value {
        Value::Number(n) if n.is_i64() || n.is_u64() => as_int(value),
        _ => None,
    }
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
        Value::Number(n) => json::number_repr(n, NumberMode::Python(FloatMode::RustShortest)),
        Value::String(s) => repr_str(s),
        Value::Array(items) => format!("[{}]", items.iter().map(py_repr).collect::<Vec<_>>().join(", ")),
        Value::Object(map) => format!(
            "{{{}}}",
            map.iter().map(|(k, v)| format!("{}: {}", repr_str(k), py_repr(v))).collect::<Vec<_>>().join(", ")
        ),
    }
}

fn repr_str(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') { '"' } else { '\'' };
    let mut out = String::from(quote);
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Python's `str.strip()`: Unicode whitespace plus the separators `\x1c`–`\x1f`.
pub fn strip(text: &str) -> &str {
    text.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;
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
            assert_eq!(json::float_repr(value, FloatMode::RustShortest), text);
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
