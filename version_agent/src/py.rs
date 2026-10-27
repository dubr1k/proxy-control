//! Version-agent-specific Python number coercions, rounding and compact HTTP JSON.
//! Shared text and JSON-value primitives live in `pc_common`.

use pc_common::json::{dumps, float_repr, FloatMode, NumberMode, Options};
use serde_json::Value;

/// `int(text)` for base 10: surrounding whitespace, an optional sign, ASCII digits with single
/// underscores between them. `None` where Python raises `ValueError` (and beyond `i64`).
pub fn int(text: &str) -> Option<i64> {
    let (negative, body) = pc_common::pytext::ascii_int_parts(text)?;
    let digits: String = body.chars().filter(|&c| c != '_').collect();
    let value: i64 = digits.parse().ok()?;
    Some(if negative { -value } else { value })
}

/// `round(value, ndigits)`: the decimal nearest to the exact binary value, ties to even, read
/// back as a float. (`f64::round` rounds ties away from zero and works on the binary value.)
pub fn round(value: f64, ndigits: usize) -> f64 {
    if !value.is_finite() {
        return value;
    }
    // 1074 fractional digits print every finite f64 exactly.
    let exact = format!("{:.1074}", value.abs());
    let (whole, fraction) = exact.split_once('.').unwrap_or((exact.as_str(), ""));
    let mut digits: Vec<u8> = whole.bytes().chain(fraction.bytes().take(ndigits)).collect();
    let rest = fraction.as_bytes().get(ndigits..).unwrap_or(&[]);
    let round_up = match rest.first() {
        Some(&d) if d > b'5' => true,
        Some(&b'5') => rest[1..].iter().any(|&d| d != b'0') || digits.last().is_some_and(|d| (d - b'0') % 2 == 1),
        _ => false,
    };
    if round_up {
        let mut index = digits.len();
        loop {
            if index == 0 {
                digits.insert(0, b'1');
                break;
            }
            index -= 1;
            if digits[index] == b'9' {
                digits[index] = b'0';
            } else {
                digits[index] += 1;
                break;
            }
        }
    }
    let split_at = digits.len() - ndigits;
    let text = format!(
        "{}.{}0",
        std::str::from_utf8(&digits[..split_at]).unwrap_or("0"),
        std::str::from_utf8(&digits[split_at..]).unwrap_or("")
    );
    let magnitude: f64 = text.parse().unwrap_or(0.0);
    if value.is_sign_negative() {
        -magnitude
    } else {
        magnitude
    }
}

/// `round(value, ndigits)` as a JSON float.
pub fn round_json(value: f64, ndigits: usize) -> Value {
    Value::from(round(value, ndigits))
}

/// `isinstance(value, int)` (a bool counts) as an `i64`.
pub fn as_int(value: &Value) -> Option<i64> {
    match value {
        Value::Bool(flag) => Some(i64::from(*flag)),
        Value::Number(number) => {
            number.as_i64().or_else(|| number.as_u64().map(|n| i64::try_from(n).unwrap_or(i64::MAX)))
        }
        _ => None,
    }
}

/// `type(value) is int` (a bool does not count).
pub fn as_strict_int(value: &Value) -> Option<i64> {
    match value {
        Value::Number(_) => as_int(value),
        _ => None,
    }
}

/// `value == 1` in Python for a JSON value (`True` and `1.0` are equal to `1`).
pub fn equals_one(value: &Value) -> bool {
    match value {
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64() == Some(1.0) && (number.is_f64() || number.as_i64() == Some(1)),
        _ => false,
    }
}

/// `str(value)` of a JSON scalar the way the upstream parsers use it (`str(x or "")`): `None`
/// for a list or an object (whose `repr` never passes a version check).
pub fn scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::Null => Some(String::new()),
        Value::Bool(true) => Some("True".into()),
        Value::Bool(false) => Some(String::new()),
        Value::Number(number) => {
            if let Some(int) = number.as_i64() {
                Some(if int == 0 { String::new() } else { int.to_string() })
            } else if let Some(int) = number.as_u64() {
                Some(int.to_string())
            } else {
                let float = number.as_f64().unwrap_or(0.0);
                Some(if float == 0.0 { String::new() } else { float_repr(float, FloatMode::Python) })
            }
        }
        Value::String(text) => Some(text.clone()),
        Value::Array(_) | Value::Object(_) => None,
    }
}

const BODY: Options = Options {
    indent: None,
    separators: Some((",", ":")),
    sort_keys: true,
    ensure_ascii: true,
    numbers: NumberMode::Python(FloatMode::Python),
};

/// `json.dumps(value, separators=(",", ":"), sort_keys=True)`: every HTTP body of the agent.
pub fn body(value: &Value) -> Vec<u8> {
    dumps(value, &BODY).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_common::pytext::{split, splitlines, strip};
    use pc_common::pyvalue::truthy;
    use serde_json::json;

    #[test]
    fn round_matches_python_round() {
        let golden: Value = serde_json::from_str(include_str!("../../tests/fixtures/host-golden/vectors/round.json"))
            .expect("round vectors");
        let mut checked = 0;
        for case in golden.as_array().unwrap() {
            let Some(ndigits) = case["ndigits"].as_u64() else { continue };
            let input: f64 = case["input_repr"].as_str().unwrap().parse().unwrap();
            let got = round(input, ndigits as usize);
            assert_eq!(float_repr(got, FloatMode::Python), case["json"].as_str().unwrap(), "round({input}, {ndigits})");
            checked += 1;
        }
        assert!(checked >= 20);
        assert_eq!(round(0.25, 1), 0.2);
        assert_eq!(round(0.35, 1), 0.3);
        assert_eq!(round(99.96, 1), 100.0);
        assert_eq!(round(-1.25, 1), -1.2);
        assert!(round(-0.04, 1).is_sign_negative());
    }

    #[test]
    fn strings_split_like_python() {
        assert_eq!(strip("\u{1c} a b \t"), "a b");
        assert_eq!(split("  a  b\u{1f}c "), vec!["a", "b", "c"]);
        assert_eq!(splitlines("a\r\nb\rc\n\nd\u{2028}e"), vec!["a", "b", "c", "", "d", "e"]);
        assert_eq!(splitlines("a\n"), vec!["a"]);
        assert!(splitlines("").is_empty());
    }

    #[test]
    fn int_parses_like_python_int() {
        assert_eq!(int(" 10001\n"), Some(10001));
        assert_eq!(int("+5"), Some(5));
        assert_eq!(int("-5"), Some(-5));
        assert_eq!(int("1_000"), Some(1000));
        for bad in ["", "_1", "1_", "1__0", "0x10", "1.0", "abc", "- 1"] {
            assert_eq!(int(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn truthiness_and_int_checks() {
        assert!(!truthy(&json!(0)) && !truthy(&json!("")) && !truthy(&json!([])) && !truthy(&json!(null)));
        assert!(truthy(&json!("false")) && truthy(&json!(0.5)));
        assert_eq!(as_int(&json!(true)), Some(1));
        assert_eq!(as_strict_int(&json!(true)), None);
        assert_eq!(as_int(&json!(1.0)), None);
        assert!(equals_one(&json!(1)) && equals_one(&json!(1.0)) && equals_one(&json!(true)));
        assert!(!equals_one(&json!(2)) && !equals_one(&json!("1")));
        assert_eq!(scalar_text(&json!(5)).as_deref(), Some("5"));
        assert_eq!(scalar_text(&json!(true)).as_deref(), Some("True"));
        assert_eq!(scalar_text(&json!(0)).as_deref(), Some(""));
        assert_eq!(scalar_text(&json!(1.5)).as_deref(), Some("1.5"));
        assert_eq!(scalar_text(&json!([1])), None);
    }

    #[test]
    fn bodies_are_compact_sorted_ascii() {
        let expected = [&br#"{"a":""#[..], b"\\", b"u00fc", br#"","b":1,"c":1.0}"#].concat();
        assert_eq!(body(&json!({"b": 1, "a": "\u{fc}", "c": 1.0})), expected);
    }
}
