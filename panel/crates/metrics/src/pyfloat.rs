//! The bits of Python float arithmetic the meters print or bucket with: `round(x, n)`, `round(x)`,
//! `format(x, ".Nf")`, float floor division, and the `isinstance` number checks of the collector.
//! Checked against `tests/fixtures/floats.json` (recorded from Python 3.13).
//!
//! Rust's fixed-precision formatting is exact and rounds ties to even, like CPython's
//! `_Py_dg_dtoa` mode 3, so `round(x, n)` is "format with n digits, parse back" in both.

use serde_json::{Number, Value};

/// `round(x, digits)` for a float.
pub fn round_to(x: f64, digits: usize) -> f64 {
    if !x.is_finite() {
        return x;
    }
    format!("{x:.digits$}").parse().unwrap_or(x)
}

/// `round(x)` for a float: the nearest integer, ties to even.
pub fn round_int(x: f64) -> i64 {
    x.round_ties_even() as i64
}

/// `format(x, f".{digits}f")`.
pub fn fixed(x: f64, digits: usize) -> String {
    if x.is_nan() {
        return "nan".into();
    }
    if x.is_infinite() {
        return if x > 0.0 { "inf".into() } else { "-inf".into() };
    }
    format!("{x:.digits$}")
}

/// `vx // wx` for floats (CPython `float_floor_div`).
pub fn floordiv(vx: f64, wx: f64) -> f64 {
    let modulo = vx % wx;
    let mut div = (vx - modulo) / wx;
    if modulo != 0.0 && ((wx < 0.0) != (modulo < 0.0)) {
        div -= 1.0;
    }
    if div != 0.0 {
        let mut floor = div.floor();
        if div - floor > 0.5 {
            floor += 1.0;
        }
        floor
    } else {
        0.0f64.copysign(vx / wx)
    }
}

/// `int(x)` for a float: truncation toward zero.
pub fn trunc(x: f64) -> i64 {
    x as i64
}

/// The collector's `_num`: a non-negative int or float (not a bool) as a float.
pub fn num(value: Option<&Value>) -> Option<f64> {
    match value {
        Some(Value::Number(number)) => number.as_f64().filter(|v| *v >= 0.0),
        _ => None,
    }
}

/// The collector's `_int`: a non-negative int (not a float, not a bool).
pub fn int(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Number(number)) if !number.is_f64() => number.as_i64().filter(|v| *v >= 0),
        _ => None,
    }
}

/// A JSON float (Python `float`): `1.0`, never `1`.
pub fn float(x: f64) -> Value {
    Number::from_f64(x).map(Value::Number).unwrap_or(Value::Null)
}

/// A JSON float or `null`.
pub fn opt_float(x: Option<f64>) -> Value {
    x.map(float).unwrap_or(Value::Null)
}

/// A JSON int or `null`.
pub fn opt_int(x: Option<i64>) -> Value {
    x.map(Value::from).unwrap_or(Value::Null)
}

/// Python truthiness of a JSON value.
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|v| v != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ties_go_to_even_like_python() {
        assert_eq!(round_to(0.25, 1), 0.2);
        assert_eq!(round_to(2.675, 2), 2.67); // the binary value is below the tie
        assert_eq!(round_int(2.5), 2);
        assert_eq!(round_int(3.5), 4);
        assert_eq!(fixed(0.5, 0), "0");
        assert_eq!(fixed(1.5, 0), "2");
    }

    #[test]
    fn floor_division_matches_python() {
        assert_eq!(floordiv(7.5, 2.0), 3.0);
        assert_eq!(floordiv(-7.5, 2.0), -4.0);
        assert_eq!(floordiv(1_800_000_011.0, 60.0), 30_000_000.0);
        assert!(floordiv(-0.0, 60.0).is_sign_negative());
    }

    #[test]
    fn number_checks_follow_isinstance() {
        let v = serde_json::json!({"i": 5, "f": 5.0, "n": -1, "b": true, "s": "5"});
        assert_eq!(int(v.get("i")), Some(5));
        assert_eq!(int(v.get("f")), None);
        assert_eq!(int(v.get("n")), None);
        assert_eq!(int(v.get("b")), None);
        assert_eq!(num(v.get("f")), Some(5.0));
        assert_eq!(num(v.get("i")), Some(5.0));
        assert_eq!(num(v.get("s")), None);
        assert_eq!(num(v.get("b")), None);
        assert_eq!(num(v.get("missing")), None);
    }
}
