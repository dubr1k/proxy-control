//! Python's view of a JSON value (what `json.loads` hands the Python panel): `repr()`, `str()`,
//! the type name and `==`. Error messages quote values this way (`invalid port: {'a': 1}`,
//! `input_type=dict`), and literal matching uses Python equality (`True == 1 == 1.0`).

use panel_core::pyjson::float_repr;
use panel_core::pytext;
use serde_json::{Number, Value};

/// `repr(value)`.
pub fn repr(value: &Value) -> String {
    let mut out = String::new();
    write_repr(&mut out, value);
    out
}

/// `str(value)`: a string as is, everything else as its `repr`.
pub fn str(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => repr(other),
    }
}

/// Whether `json.loads` would have made a `float` of this number (it had a fraction or an
/// exponent); integers beyond `u64` also arrive here as floats (see the crate docs).
pub fn is_float(number: &Number) -> bool {
    number.is_f64()
}

fn write_repr(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("None"),
        Value::Bool(true) => out.push_str("True"),
        Value::Bool(false) => out.push_str("False"),
        Value::Number(number) => out.push_str(&number_repr(number)),
        Value::String(text) => out.push_str(&pytext::repr(text)),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write_repr(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (index, (key, item)) in map.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                out.push_str(&pytext::repr(key));
                out.push_str(": ");
                write_repr(out, item);
            }
            out.push('}');
        }
    }
}

/// `repr()` of a JSON number: Python's `int` or `float` text.
pub fn number_repr(number: &Number) -> String {
    if let Some(value) = number.as_i64() {
        value.to_string()
    } else if let Some(value) = number.as_u64() {
        value.to_string()
    } else {
        float_repr(number.as_f64().unwrap_or(f64::NAN))
    }
}

/// A JSON number as Python compares it: exactly, across `int`, `float` and `bool`.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Numeric {
    Int(i128),
    Float(f64),
}

fn numeric(value: &Value) -> Option<Numeric> {
    match value {
        Value::Bool(flag) => Some(Numeric::Int(i128::from(*flag))),
        Value::Number(number) => Some(if let Some(value) = number.as_i64() {
            Numeric::Int(i128::from(value))
        } else if let Some(value) = number.as_u64() {
            Numeric::Int(i128::from(value))
        } else {
            Numeric::Float(number.as_f64().unwrap_or(f64::NAN))
        }),
        _ => None,
    }
}

fn numeric_eq(a: Numeric, b: Numeric) -> bool {
    match (a, b) {
        (Numeric::Int(a), Numeric::Int(b)) => a == b,
        (Numeric::Float(a), Numeric::Float(b)) => a == b,
        (Numeric::Int(int), Numeric::Float(float)) | (Numeric::Float(float), Numeric::Int(int)) => {
            // Python compares an int and a float exactly (no rounding of the int).
            float.is_finite() && float.fract() == 0.0 && float.abs() < 1.8e19 && float as i128 == int
        }
    }
}

/// Python's `a == b` for JSON values: numbers and booleans compare by value (`True == 1 == 1.0`),
/// dicts ignore key order, lists compare item by item.
pub fn eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Array(a), Value::Array(b)) => a.len() == b.len() && a.iter().zip(b).all(|(a, b)| eq(a, b)),
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len() && a.iter().all(|(key, value)| b.get(key).is_some_and(|other| eq(value, other)))
        }
        _ => match (numeric(a), numeric(b)) {
            (Some(a), Some(b)) => numeric_eq(a, b),
            _ => false,
        },
    }
}

/// pydantic-core's `truncate_safe_repr`: a `repr` longer than 50 bytes keeps its first 25 and last
/// 24 bytes around `...` (cut at character boundaries, inwards).
pub fn truncated_repr(value: &Value) -> String {
    const LIMIT: usize = 50;
    let text = repr(value);
    if text.len() <= LIMIT {
        return text;
    }
    let mid = LIMIT.div_ceil(2);
    let mut head_end = mid;
    while !text.is_char_boundary(head_end) {
        head_end -= 1;
    }
    let mut tail_start = text.len() - (LIMIT - mid - 1);
    while !text.is_char_boundary(tail_start) {
        tail_start += 1;
    }
    format!("{}...{}", &text[..head_end], &text[tail_start..])
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn python_equality_crosses_int_float_and_bool() {
        assert!(eq(&json!(1), &json!(true)));
        assert!(eq(&json!(1.0), &json!(1)));
        assert!(eq(&json!(0), &json!(false)));
        assert!(!eq(&json!("1"), &json!(1)));
        assert!(eq(&json!({"a": [1, {"b": null}], "c": 2}), &json!({"c": 2.0, "a": [true, {"b": null}]})));
        assert!(!eq(&json!({"a": 1}), &json!({"a": 1, "b": 2})));
        assert!(!eq(&json!(1.5), &json!(1)));
    }

    #[test]
    fn long_reprs_are_cut_in_the_middle_on_character_boundaries() {
        assert_eq!(truncated_repr(&json!("a".repeat(65))), format!("'{}...{}'", "a".repeat(24), "a".repeat(23)));
        assert_eq!(truncated_repr(&json!("Ж".repeat(129))), format!("'{}...{}'", "Ж".repeat(12), "Ж".repeat(11)));
        assert_eq!(truncated_repr(&json!("short")), "'short'");
    }
}
