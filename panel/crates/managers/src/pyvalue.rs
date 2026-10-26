//! Python semantics over JSON values that the clients rely on: truthiness, `==` (where
//! `True == 1 == 1.0`), `parse_qs` and the path quoting httpx applies to a request URL.

use serde_json::Value;

/// `bool(value)` for a value `json.loads` produced.
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

/// Python's `a == b` for values `json.loads` produced: `bool` is an `int`, and an `int` equals the
/// `float` of the same value; dicts compare without regard to key order.
pub fn py_eq(a: &Value, b: &Value) -> bool {
    fn numeric(value: &Value) -> Option<Numeric> {
        match value {
            Value::Bool(flag) => Some(Numeric::Int(i128::from(*flag))),
            Value::Number(number) => Some(if let Some(int) = number.as_i64() {
                Numeric::Int(i128::from(int))
            } else if let Some(int) = number.as_u64() {
                Numeric::Int(i128::from(int))
            } else {
                Numeric::Float(number.as_f64().unwrap_or(f64::NAN))
            }),
            _ => None,
        }
    }
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(x, y)| py_eq(x, y)),
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(key, value)| y.get(key).is_some_and(|other| py_eq(value, other)))
        }
        _ => match (numeric(a), numeric(b)) {
            (Some(Numeric::Int(x)), Some(Numeric::Int(y))) => x == y,
            (Some(Numeric::Int(x)), Some(Numeric::Float(y))) | (Some(Numeric::Float(y)), Some(Numeric::Int(x))) => {
                y.fract() == 0.0 && y.is_finite() && (y as i128) == x && y.abs() < 1.7e38
            }
            (Some(Numeric::Float(x)), Some(Numeric::Float(y))) => x == y,
            _ => false,
        },
    }
}

enum Numeric {
    Int(i128),
    Float(f64),
}

/// The first value of `name` in `urllib.parse.parse_qs(query)` (default arguments: blank values
/// and fields without `=` dropped, `&` the only separator, `+` a space, `%XX` decoded as UTF-8
/// with replacement).
pub fn parse_qs_first(query: &str, name: &str) -> Option<String> {
    for field in query.split('&') {
        if field.is_empty() {
            continue;
        }
        let Some((key, value)) = field.split_once('=') else { continue };
        if value.is_empty() {
            continue;
        }
        let key = panel_core::pytext::unquote(&key.replace('+', " "));
        if key == name {
            return Some(panel_core::pytext::unquote(&value.replace('+', " ")));
        }
    }
    None
}

/// What httpx sends for a request path given as a string: the query split off at the first `?`,
/// anything after `#` dropped, and every character outside the unreserved set, the sub-delimiters
/// and `:/[]@` (plus `?` in the query) percent-encoded as UTF-8, while valid `%XX` sequences stay
/// (`httpx/_urlparse.py` `quote`).
pub fn httpx_target(target: &str) -> String {
    let target = target.split('#').next().unwrap_or("");
    match target.split_once('?') {
        Some((path, query)) => format!("{}?{}", quote_keep_escapes(path, ":/[]@"), quote_keep_escapes(query, ":/?[]@")),
        None => quote_keep_escapes(target, ":/[]@"),
    }
}

fn quote_keep_escapes(text: &str, safe: &str) -> String {
    const SUB_DELIMS: &[u8] = b"!$&'()*+,;=";
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%'
            && index + 2 < bytes.len()
            && bytes[index + 1].is_ascii_hexdigit()
            && bytes[index + 2].is_ascii_hexdigit()
        {
            out.push_str(&text[index..index + 3]);
            index += 3;
            continue;
        }
        if byte.is_ascii_alphanumeric()
            || b"-._~".contains(&byte)
            || SUB_DELIMS.contains(&byte)
            || safe.as_bytes().contains(&byte)
        {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
        index += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn truthiness_follows_python() {
        for (value, expected) in [
            (json!(null), false),
            (json!(true), true),
            (json!(0), false),
            (json!(0.0), false),
            (json!(2), true),
            (json!(""), false),
            (json!("x"), true),
            (json!([]), false),
            (json!({}), false),
            (json!({"a": 1}), true),
        ] {
            assert_eq!(truthy(&value), expected, "{value}");
        }
    }

    #[test]
    fn equality_follows_python() {
        assert!(py_eq(&json!({"a": true, "b": [1]}), &json!({"b": [1.0], "a": 1})));
        assert!(!py_eq(&json!({"a": true}), &json!({"a": 2})));
        assert!(!py_eq(&json!({"a": "1"}), &json!({"a": 1})));
        assert!(!py_eq(&json!({"a": 1}), &json!({"a": 1, "b": null})));
        assert!(py_eq(&json!(false), &json!(0)));
        assert!(!py_eq(&json!(null), &json!(false)));
    }

    #[test]
    fn parse_qs_matches_urllib() {
        let query = "server=a%2Eb&port=&x&secret=ee+1%20&secret=second";
        assert_eq!(parse_qs_first(query, "server").as_deref(), Some("a.b"));
        assert_eq!(parse_qs_first(query, "port"), None);
        assert_eq!(parse_qs_first(query, "x"), None);
        assert_eq!(parse_qs_first(query, "secret").as_deref(), Some("ee 1 "));
    }

    #[test]
    fn targets_are_quoted_like_httpx() {
        assert_eq!(httpx_target("/v1/users/alice"), "/v1/users/alice");
        assert_eq!(httpx_target("/v1/lanes/naive/grant:a b"), "/v1/lanes/naive/grant:a%20b");
        assert_eq!(httpx_target("/v1/x/%2F/%zz/é"), "/v1/x/%2F/%25zz/%C3%A9");
        assert_eq!(httpx_target("/v1/x?a=b c#frag"), "/v1/x?a=b%20c");
    }
}
