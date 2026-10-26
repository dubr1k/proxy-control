//! Python's view of a decoded JSON value: `str(x)`, `int(x)`, truthiness and `x == n`.

use panel_core::pyjson;
use panel_core::pytext;
use panel_core::serde_json::Value;

/// `str(value)` for a JSON scalar (`None`, `True`, `1`, `1.5`, the string itself). Python would
/// also stringify a list or dict with `repr`; those are refused here (`None`).
pub(crate) fn py_str(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Null => Some("None".into()),
        Value::Bool(true) => Some("True".into()),
        Value::Bool(false) => Some("False".into()),
        Value::Number(number) => Some(match (number.as_i64(), number.as_u64(), number.as_f64()) {
            (Some(value), _, _) => value.to_string(),
            (None, Some(value), _) => value.to_string(),
            (None, None, Some(value)) => pyjson::float_repr(value),
            _ => return None,
        }),
        Value::Array(_) | Value::Object(_) => None,
    }
}

/// `int(value)` for a JSON value: integers, booleans, floats (truncated) and decimal strings
/// (`" 12 "`, `"1_000"`). `None` where Python raises `TypeError`/`ValueError`, and for values
/// outside `i64` (Python's ints are unbounded).
pub(crate) fn py_int(value: &Value) -> Option<i64> {
    match value {
        Value::Bool(flag) => Some(i64::from(*flag)),
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                return Some(value);
            }
            if number.as_u64().is_some() {
                return None;
            }
            let value = number.as_f64()?.trunc();
            // i64::MAX is not representable as f64; 2^63 is the first value out of range.
            (-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0).contains(&value).then_some(value as i64)
        }
        Value::String(text) => pytext::int_from_str(text).ok(),
        _ => None,
    }
}

/// `value == number` with Python's numeric equality (`1 == 1.0 == True`).
pub(crate) fn py_eq_int(value: &Value, expected: i64) -> bool {
    match value {
        Value::Bool(flag) => i64::from(*flag) == expected,
        Value::Number(number) => match (number.as_i64(), number.as_f64()) {
            (Some(value), _) => value == expected,
            (None, Some(value)) => number.as_u64().is_none() && value == expected as f64,
            _ => false,
        },
        _ => false,
    }
}

/// `bool(value)`.
pub(crate) fn py_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|value| value != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use panel_core::serde_json::json;

    #[test]
    fn str_of_scalars_is_python_str() {
        assert_eq!(py_str(&json!("k-1")).as_deref(), Some("k-1"));
        assert_eq!(py_str(&json!(null)).as_deref(), Some("None"));
        assert_eq!(py_str(&json!(true)).as_deref(), Some("True"));
        assert_eq!(py_str(&json!(123)).as_deref(), Some("123"));
        assert_eq!(py_str(&json!(1.5)).as_deref(), Some("1.5"));
        assert_eq!(py_str(&json!(1e16)).as_deref(), Some("1e+16"));
        assert_eq!(py_str(&json!([1])), None);
    }

    #[test]
    fn int_of_values_is_python_int() {
        assert_eq!(py_int(&json!(true)), Some(1));
        assert_eq!(py_int(&json!(1.9)), Some(1));
        assert_eq!(py_int(&json!(-1.9)), Some(-1));
        assert_eq!(py_int(&json!(" 12 ")), Some(12));
        assert_eq!(py_int(&json!("1_000")), Some(1000));
        assert_eq!(py_int(&json!("1.5")), None);
        assert_eq!(py_int(&json!(null)), None);
        assert_eq!(py_int(&json!(1e19)), None);
        assert_eq!(py_int(&json!(u64::MAX)), None);
    }

    #[test]
    fn equality_and_truthiness_follow_python() {
        assert!(py_eq_int(&json!(1), 1) && py_eq_int(&json!(1.0), 1) && py_eq_int(&json!(true), 1));
        assert!(!py_eq_int(&json!("1"), 1) && !py_eq_int(&json!(null), 1) && !py_eq_int(&json!(2), 1));
        assert!(!py_truthy(&json!("")) && !py_truthy(&json!(0)) && !py_truthy(&json!(0.0)) && !py_truthy(&json!({})));
        assert!(py_truthy(&json!("x")) && py_truthy(&json!(-1)) && py_truthy(&json!([0])));
    }
}
