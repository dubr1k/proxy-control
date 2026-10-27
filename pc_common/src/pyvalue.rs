//! Compatible Python primitives over ordinary `serde_json::Value` values.
//!
//! Numeric equality and coercion stay with their consumers: their accepted ranges and
//! treatment of large integers versus floats are not interchangeable.

use serde_json::Value;

/// `bool(value)` for a decoded JSON value.
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|n| n != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// `type(value).__name__` for an ordinary decoded JSON value.
pub fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(number) if number.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// A JSON integer (not a bool or float), preserving both signed and unsigned 64-bit values.
pub fn strict_int(value: &Value) -> Option<i128> {
    match value {
        Value::Number(number) if !number.is_f64() => {
            number.as_i64().map(i128::from).or_else(|| number.as_u64().map(i128::from))
        }
        _ => None,
    }
}
