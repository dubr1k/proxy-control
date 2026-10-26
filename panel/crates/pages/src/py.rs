//! Python's view of a decoded JSON value, as far as the pages need it: `isinstance` checks,
//! `int(x or 0)`, `len(x)`, iterating a value, `round(x, n)` — with the crashes Python would have
//! (an `AttributeError` on `.get` of a non-dict, a `TypeError` on iterating `None`) as
//! [`Fault::Crash`].

use serde_json::{json, Map, Number, Value};

use crate::{Fault, PageResult};

/// `type(value).__name__` for a crash message.
fn type_name(value: &Value) -> &'static str {
    panel_model::pyrepr::type_name(value)
}

/// `value.get(...)` needs a dict: anything else is an `AttributeError`.
pub fn dict(value: &Value) -> PageResult<&Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| Fault::crash(format!("AttributeError: '{}' object has no attribute 'get'", type_name(value))))
}

/// `value if isinstance(value, dict) else None`.
pub fn as_dict(value: Option<&Value>) -> Option<&Map<String, Value>> {
    value.and_then(Value::as_object)
}

/// `isinstance(value, int) and not isinstance(value, bool)`.
pub fn is_int(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Number(number)) if !number.is_f64())
}

/// `isinstance(value, int) and not isinstance(value, bool) and value >= 0`.
pub fn non_negative_int(value: Option<&Value>) -> Option<&Value> {
    match value {
        Some(Value::Number(number)) if number.as_u64().is_some() => value,
        _ => None,
    }
}

/// `isinstance(value, (int, float)) and not isinstance(value, bool)`, as a float.
pub fn number(value: Option<&Value>) -> Option<f64> {
    match value {
        Some(Value::Number(number)) => number.as_f64(),
        _ => None,
    }
}

/// `value is True`.
pub fn is_true(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Bool(true)))
}

/// `value is False`.
pub fn is_false(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Bool(false)))
}

/// `str(value)`.
pub fn py_str(value: &Value) -> String {
    panel_model::pyrepr::str(value)
}

/// Python truthiness.
pub fn truthy(value: Option<&Value>) -> bool {
    value.is_some_and(panel_managers::pyvalue::truthy)
}

/// `a == b` with Python's rules (`1 == 1.0 == True`).
pub fn eq(a: &Value, b: &Value) -> bool {
    panel_model::pyrepr::eq(a, b)
}

/// The dicts among the items of `for item in value` (a dict iterates its keys and a string its
/// characters — neither is a dict); `None`, a number or a boolean cannot be iterated.
pub fn dict_items(value: &Value) -> PageResult<Vec<&Map<String, Value>>> {
    match value {
        Value::Array(items) => Ok(items.iter().filter_map(Value::as_object).collect()),
        Value::Object(_) | Value::String(_) => Ok(Vec::new()),
        other => Err(Fault::crash(format!("TypeError: '{}' object is not iterable", type_name(other)))),
    }
}

/// `len(value)`.
pub fn py_len(value: &Value) -> PageResult<usize> {
    match value {
        Value::Array(items) => Ok(items.len()),
        Value::Object(map) => Ok(map.len()),
        Value::String(text) => Ok(text.chars().count()),
        other => Err(Fault::crash(format!("TypeError: object of type '{}' has no len()", type_name(other)))),
    }
}

/// `list(value or [])`: a list stays as it is, a string becomes its characters, a dict its keys.
pub fn list_or_empty(value: Option<&Value>) -> PageResult<Vec<Value>> {
    if !truthy(value) {
        return Ok(Vec::new());
    }
    match value {
        Some(Value::Array(items)) => Ok(items.clone()),
        Some(Value::String(text)) => Ok(text.chars().map(|ch| Value::String(ch.to_string())).collect()),
        Some(Value::Object(map)) => Ok(map.keys().map(|key| Value::String(key.clone())).collect()),
        Some(other) => Err(Fault::crash(format!("TypeError: '{}' object is not iterable", type_name(other)))),
        None => Ok(Vec::new()),
    }
}

/// `int(value or 0)`: falsy is 0, a bool 0/1, an int itself, a float truncated, a string parsed
/// like `int()`; anything else is a crash.
pub fn int_or_zero(value: Option<&Value>) -> PageResult<i128> {
    if !truthy(value) {
        return Ok(0);
    }
    match value {
        Some(Value::Bool(flag)) => Ok(i128::from(*flag)),
        Some(Value::Number(number)) => Ok(int_of(number)),
        Some(Value::String(text)) => panel_core::pytext::int_from_str(text)
            .map(i128::from)
            .map_err(|error| Fault::crash(format!("ValueError: {}", error.0))),
        Some(other) => Err(Fault::crash(format!(
            "TypeError: int() argument must be a string, a bytes-like object or a real number, not '{}'",
            type_name(other)
        ))),
        None => Ok(0),
    }
}

fn int_of(number: &Number) -> i128 {
    if let Some(value) = number.as_i64() {
        i128::from(value)
    } else if let Some(value) = number.as_u64() {
        i128::from(value)
    } else {
        let float = number.as_f64().unwrap_or(0.0);
        // `int(float)` truncates; beyond i128 the panel has nothing sensible to show anyway.
        float.trunc().clamp(i128::MIN as f64, i128::MAX as f64) as i128
    }
}

/// The integer of a JSON number that is an integer (`isinstance(value, int)`; bools count as 0/1
/// like Python's), else `None`.
pub fn integer(value: &Value) -> Option<i128> {
    match value {
        Value::Bool(flag) => Some(i128::from(*flag)),
        Value::Number(number) if !number.is_f64() => Some(int_of(number)),
        _ => None,
    }
}

/// A Python int as JSON (beyond 64 bits saturated: no counter of the panel gets there).
pub fn int_value(value: i128) -> Value {
    if let Ok(small) = i64::try_from(value) {
        json!(small)
    } else if let Ok(large) = u64::try_from(value) {
        json!(large)
    } else if value < 0 {
        json!(i64::MIN)
    } else {
        json!(u64::MAX)
    }
}

/// `round(x, digits)` of a float: format exactly with `digits` decimals (ties to even on the exact
/// binary value, like CPython's `_Py_dg_dtoa` mode 3) and parse back.
pub fn round_to(x: f64, digits: usize) -> f64 {
    if !x.is_finite() {
        return x;
    }
    format!("{x:.digits$}").parse().unwrap_or(x)
}

/// A float as JSON (`float` keeps its `.0` through the panel's JSON writer).
pub fn float_value(x: f64) -> Value {
    Number::from_f64(x).map_or(Value::Null, Value::Number)
}

/// `[A-Za-z0-9_.-]{1,64}` as `re.fullmatch` reads it.
pub fn account_name(text: &str) -> bool {
    let count = text.chars().count();
    (1..=64).contains(&count) && text.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'))
}

/// `value in {"manual", "quota"}`-style membership: an unhashable value (list, dict) is a
/// `TypeError`, anything else compares with `==`.
pub fn member<'a>(value: Option<&'a Value>, choices: &[&str]) -> PageResult<Option<&'a Value>> {
    match value {
        Some(Value::Array(_)) | Some(Value::Object(_)) => {
            Err(Fault::crash(format!("TypeError: unhashable type: '{}'", type_name(value.unwrap_or(&Value::Null)))))
        }
        Some(Value::String(text)) if choices.contains(&text.as_str()) => Ok(value),
        _ => Ok(None),
    }
}

/// A dict key lookup with a JSON value as the key (`mapping.get(value)`): only a string can be a
/// key of a JSON object; an unhashable value is a `TypeError`.
pub fn key_of(value: Option<&Value>) -> PageResult<Option<&str>> {
    match value {
        Some(Value::String(text)) => Ok(Some(text)),
        Some(other @ (Value::Array(_) | Value::Object(_))) => {
            Err(Fault::crash(format!("TypeError: unhashable type: '{}'", type_name(other))))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ints_follow_python() {
        assert_eq!(int_or_zero(None).unwrap(), 0);
        assert_eq!(int_or_zero(Some(&json!(null))).unwrap(), 0);
        assert_eq!(int_or_zero(Some(&json!(""))).unwrap(), 0);
        assert_eq!(int_or_zero(Some(&json!(true))).unwrap(), 1);
        assert_eq!(int_or_zero(Some(&json!(12.9))).unwrap(), 12);
        assert_eq!(int_or_zero(Some(&json!(" 42 "))).unwrap(), 42);
        assert!(int_or_zero(Some(&json!("1.5"))).is_err());
        assert!(int_or_zero(Some(&json!([1]))).is_err());
        assert_eq!(int_or_zero(Some(&json!(u64::MAX))).unwrap(), i128::from(u64::MAX));
        assert_eq!(int_value(i128::from(u64::MAX)), json!(u64::MAX));
    }

    #[test]
    fn rounding_is_python_round() {
        assert_eq!(round_to(81.25, 1), 81.2);
        assert_eq!(round_to(27.35, 1), 27.4); // 27.35 is 27.350000000000001…
        assert_eq!(round_to(0.125, 2), 0.12);
        assert_eq!(round_to(0.5, 2), 0.5);
        assert_eq!(float_value(100.0), json!(100.0));
    }

    #[test]
    fn iteration_and_len_follow_python() {
        assert_eq!(dict_items(&json!([{"a": 1}, 2, "x"])).unwrap().len(), 1);
        assert!(dict_items(&json!({"a": 1})).unwrap().is_empty());
        assert!(dict_items(&json!(null)).is_err());
        assert_eq!(py_len(&json!("ab\u{e9}")).unwrap(), 3);
        assert!(py_len(&json!(5)).is_err());
        assert_eq!(list_or_empty(Some(&json!("ab"))).unwrap(), vec![json!("a"), json!("b")]);
        assert!(list_or_empty(Some(&json!(0))).unwrap().is_empty());
        assert!(list_or_empty(Some(&json!(3))).is_err());
        assert!(member(Some(&json!(["x"])), &["manual"]).is_err());
        assert_eq!(member(Some(&json!("manual")), &["manual"]).unwrap(), Some(&json!("manual")));
        assert_eq!(member(Some(&json!(1)), &["manual"]).unwrap(), None);
    }

    #[test]
    fn account_names_are_ascii_and_bounded() {
        assert!(account_name("phone_1.a-b"));
        assert!(!account_name(""));
        assert!(!account_name("bad user"));
        assert!(!account_name("caf\u{e9}"));
        assert!(!account_name(&"a".repeat(65)));
    }
}
