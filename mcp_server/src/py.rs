//! The Python semantics the server's behaviour rests on: truthiness, `str()`/`repr()`, dict and
//! iteration errors with Python's own messages, `int()`, `str.strip()`, `urllib.parse.quote`,
//! `urlencode` and `json.dumps` with Python's separators and float formatting.
//!
//! A tool handler of the Python server that hit a `KeyError` or `TypeError` answered the MCP
//! client with a JSON-RPC error whose message was `str(exc)`; [`PyErr`] carries that message.

use std::io;

use pc_common::pytext::strip;
use pc_common::pyvalue::type_name;
use serde_json::{Map, Value};

/// A Python exception escaping a handler: the JSON-RPC error message is `str(exc)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyErr {
    pub kind: &'static str,
    pub message: String,
}

impl PyErr {
    pub fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self { kind, message: message.into() }
    }

    pub fn type_error(message: impl Into<String>) -> Self {
        Self::new("TypeError", message)
    }

    pub fn attribute(value: &Value, attribute: &str) -> Self {
        Self::new("AttributeError", format!("'{}' object has no attribute '{attribute}'", type_name(value)))
    }

    /// `KeyError(key)`: `str()` of a KeyError is the key's `repr()`.
    pub fn key(key: &str) -> Self {
        Self::new("KeyError", repr_str(key))
    }
}

impl std::fmt::Display for PyErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// `a == b` between JSON-decoded Python values (`1 == 1.0 == True`).
pub fn eq(a: &Value, b: &Value) -> bool {
    fn numeric(value: &Value) -> Option<f64> {
        match value {
            Value::Bool(flag) => Some(f64::from(u8::from(*flag))),
            Value::Number(number) => number.as_f64(),
            _ => None,
        }
    }
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| eq(p, q)),
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(key, p)| y.get(key).is_some_and(|q| eq(p, q)))
        }
        (Value::Number(x), Value::Number(y)) if x.is_f64() || y.is_f64() => x.as_f64() == y.as_f64(),
        (Value::Number(x), Value::Number(y)) => x == y,
        _ => match (numeric(a), numeric(b)) {
            (Some(x), Some(y)) => x == y,
            _ => false,
        },
    }
}

/// `d.get(key)` (the value may be missing): only a dict has `.get`.
pub fn get<'a>(value: &'a Value, key: &str) -> Result<Option<&'a Value>, PyErr> {
    match value {
        Value::Object(map) => Ok(map.get(key)),
        other => Err(PyErr::attribute(other, "get")),
    }
}

/// `d.get(key, default)` with the default owned.
pub fn get_or(value: &Value, key: &str, default: Value) -> Result<Value, PyErr> {
    Ok(get(value, key)?.cloned().unwrap_or(default))
}

/// `d[key]` with a string key.
pub fn getitem<'a>(value: &'a Value, key: &str) -> Result<&'a Value, PyErr> {
    match value {
        Value::Object(map) => map.get(key).ok_or_else(|| PyErr::key(key)),
        Value::String(_) => Err(PyErr::type_error("string indices must be integers, not 'str'")),
        Value::Array(_) => Err(PyErr::type_error("list indices must be integers or slices, not str")),
        other => Err(PyErr::type_error(format!("'{}' object is not subscriptable", type_name(other)))),
    }
}

/// `d.items()`.
pub fn items(value: &Value) -> Result<Vec<(String, Value)>, PyErr> {
    match value {
        Value::Object(map) => Ok(map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()),
        other => Err(PyErr::attribute(other, "items")),
    }
}

/// `for item in value` / `list(value)`: a dict yields its keys, a string its characters.
pub fn iterate(value: &Value) -> Result<Vec<Value>, PyErr> {
    match value {
        Value::Array(items) => Ok(items.clone()),
        Value::Object(map) => Ok(map.keys().map(|key| Value::String(key.clone())).collect()),
        Value::String(text) => Ok(text.chars().map(|c| Value::String(c.to_string())).collect()),
        other => Err(PyErr::type_error(format!("'{}' object is not iterable", type_name(other)))),
    }
}

/// `needle in container` for a string needle.
pub fn contains(container: &Value, needle: &str) -> Result<bool, PyErr> {
    match container {
        Value::Object(map) => Ok(map.contains_key(needle)),
        Value::Array(items) => Ok(items.iter().any(|item| item.as_str() == Some(needle))),
        Value::String(text) => Ok(text.contains(needle)),
        other => Err(PyErr::type_error(format!("argument of type '{}' is not iterable", type_name(other)))),
    }
}

/// `value.strip()` on something that must be a string.
pub fn strip_method(value: &Value) -> Result<String, PyErr> {
    match value {
        Value::String(text) => Ok(strip(text).to_string()),
        other => Err(PyErr::attribute(other, "strip")),
    }
}

/// `str(value)`.
pub fn str_of(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => repr(other),
    }
}

/// `repr(value)`.
pub fn repr(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(number) => match number.as_f64() {
            Some(float) if number.is_f64() => float_repr(float),
            _ => number.to_string(),
        },
        Value::String(text) => repr_str(text),
        Value::Array(items) => format!("[{}]", items.iter().map(repr).collect::<Vec<_>>().join(", ")),
        Value::Object(map) => format!(
            "{{{}}}",
            map.iter().map(|(k, v)| format!("{}: {}", repr_str(k), repr(v))).collect::<Vec<_>>().join(", ")
        ),
    }
}

/// Characters `repr()` writes as escapes (an approximation of `str.isprintable()` beyond ASCII:
/// controls, format characters, separators other than the space, private use).
fn is_printable(c: char) -> bool {
    let code = c as u32;
    if code < 0x20 || code == 0x7f {
        return false;
    }
    if code < 0x7f {
        return true;
    }
    !matches!(code,
        0x80..=0xa0 | 0xad | 0x600..=0x605 | 0x61c | 0x6dd | 0x70f | 0x1680 | 0x180e | 0x2000..=0x200f
        | 0x2028..=0x202f | 0x205f..=0x2064 | 0x2066..=0x206f | 0x3000 | 0xd800..=0xf8ff | 0xfeff
        | 0xfff9..=0xfffb | 0xfffe | 0xffff | 0xe0001 | 0xe0020..=0xe007f | 0xf0000..)
}

/// `repr(text)`.
pub fn repr_str(text: &str) -> String {
    pc_common::pytext::repr_with_printable(text, is_printable)
}

/// `repr(float)`: the shortest round-trip digits, positional between 1e-4 and 1e16, else
/// `d.ddde±XX`.
pub fn float_repr(value: f64) -> String {
    if value.is_nan() {
        return "nan".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "inf".into() } else { "-inf".into() };
    }
    let sign = if value.is_sign_negative() { "-" } else { "" };
    let lower = format!("{:e}", value.abs());
    let (mantissa, exponent) = lower.split_once('e').unwrap_or((&lower, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let digits = if digits.chars().all(|c| c == '0') { "0".to_string() } else { digits };
    let point = exponent + 1;
    let body = if !(-3..=16).contains(&point) {
        let (first, rest) = digits.split_at(1);
        let fraction = if rest.is_empty() { String::new() } else { format!(".{rest}") };
        let exp_sign = if exponent < 0 { '-' } else { '+' };
        format!("{first}{fraction}e{exp_sign}{:02}", exponent.abs())
    } else if point <= 0 {
        format!("0.{}{digits}", "0".repeat(point.unsigned_abs() as usize))
    } else if point as usize >= digits.len() {
        format!("{digits}{}.0", "0".repeat(point as usize - digits.len()))
    } else {
        let (whole, fraction) = digits.split_at(point as usize);
        format!("{whole}.{fraction}")
    };
    format!("{sign}{body}")
}

/// `int(value)` as its decimal text, with Python's errors.
pub fn int_of(value: &Value) -> Result<String, PyErr> {
    match value {
        Value::Bool(flag) => Ok(u8::from(*flag).to_string()),
        Value::Number(number) if number.is_f64() => {
            let float = number.as_f64().unwrap_or(0.0).trunc();
            if float == 0.0 {
                Ok("0".into())
            } else {
                Ok(format!("{float:.0}"))
            }
        }
        Value::Number(number) => Ok(number.to_string()),
        Value::String(text) => parse_int(text).ok_or_else(|| {
            PyErr::new("ValueError", format!("invalid literal for int() with base 10: {}", repr_str(text)))
        }),
        other => Err(PyErr::type_error(format!(
            "int() argument must be a string, a bytes-like object or a real number, not '{}'",
            type_name(other)
        ))),
    }
}

fn parse_int(text: &str) -> Option<String> {
    let (negative, digits) = pc_common::pytext::ascii_int_parts(text)?;
    let clean: String = digits.chars().filter(char::is_ascii_digit).collect();
    let clean = clean.trim_start_matches('0');
    Some(match (clean.is_empty(), negative) {
        (true, _) => "0".into(),
        (false, true) => format!("-{clean}"),
        (false, false) => clean.to_string(),
    })
}

const ALWAYS_SAFE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-~";

/// `urllib.parse.quote(text, safe="")`.
pub fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if ALWAYS_SAFE.contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// `urllib.parse.quote_plus(text)`: what `urlencode` writes for keys and values.
pub fn quote_plus(text: &str) -> String {
    quote(text).replace("%20", "+")
}

/// One query parameter value as httpx writes it: JSON-style booleans, empty for None.
pub fn query_value(value: &Value) -> String {
    match value {
        Value::Bool(true) => "true".into(),
        Value::Bool(false) => "false".into(),
        Value::Null => String::new(),
        other => str_of(other),
    }
}

/// `urlencode()` of httpx's query parameters: a list value repeats its key; an empty list drops it.
pub fn urlencode(params: &[(String, Value)]) -> String {
    let mut pairs = Vec::new();
    for (key, value) in params {
        let values = match value {
            Value::Array(items) => items.clone(),
            other => vec![other.clone()],
        };
        for item in values {
            pairs.push(format!("{}={}", quote_plus(key), quote_plus(&query_value(&item))));
        }
    }
    pairs.join("&")
}

/// `json.dumps`: with `indent=1` (the tools' text) or with the default `", "`/`": "` separators.
pub fn dumps(value: &Value, indent: bool) -> String {
    let mut out = Vec::new();
    let formatter = PyFormatter { pretty: indent, level: 0, has_value: false };
    let mut serializer = serde_json::Serializer::with_formatter(&mut out, formatter);
    serde::Serialize::serialize(value, &mut serializer).expect("a JSON value always serialises");
    String::from_utf8(out).expect("serde_json writes UTF-8")
}

struct PyFormatter {
    pretty: bool,
    level: usize,
    has_value: bool,
}

impl PyFormatter {
    fn separator<W: ?Sized + io::Write>(&self, writer: &mut W, first: bool) -> io::Result<()> {
        if self.pretty {
            writer.write_all(if first { b"\n" } else { b",\n" })?;
            writer.write_all(" ".repeat(self.level).as_bytes())
        } else if first {
            Ok(())
        } else {
            writer.write_all(b", ")
        }
    }

    fn close<W: ?Sized + io::Write>(&mut self, writer: &mut W, bracket: &[u8]) -> io::Result<()> {
        self.level -= 1;
        if self.pretty && self.has_value {
            writer.write_all(b"\n")?;
            writer.write_all(" ".repeat(self.level).as_bytes())?;
        }
        writer.write_all(bracket)
    }
}

impl serde_json::ser::Formatter for PyFormatter {
    fn write_f64<W: ?Sized + io::Write>(&mut self, writer: &mut W, value: f64) -> io::Result<()> {
        writer.write_all(float_repr(value).as_bytes())
    }

    fn write_f32<W: ?Sized + io::Write>(&mut self, writer: &mut W, value: f32) -> io::Result<()> {
        writer.write_all(float_repr(f64::from(value)).as_bytes())
    }

    fn begin_array<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.level += 1;
        self.has_value = false;
        writer.write_all(b"[")
    }

    fn end_array<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.close(writer, b"]")
    }

    fn begin_array_value<W: ?Sized + io::Write>(&mut self, writer: &mut W, first: bool) -> io::Result<()> {
        self.separator(writer, first)
    }

    fn end_array_value<W: ?Sized + io::Write>(&mut self, _writer: &mut W) -> io::Result<()> {
        self.has_value = true;
        Ok(())
    }

    fn begin_object<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.level += 1;
        self.has_value = false;
        writer.write_all(b"{")
    }

    fn end_object<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.close(writer, b"}")
    }

    fn begin_object_key<W: ?Sized + io::Write>(&mut self, writer: &mut W, first: bool) -> io::Result<()> {
        self.separator(writer, first)
    }

    fn begin_object_value<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        writer.write_all(b": ")
    }

    fn end_object_value<W: ?Sized + io::Write>(&mut self, _writer: &mut W) -> io::Result<()> {
        self.has_value = true;
        Ok(())
    }
}

/// An ordered map with Python dict semantics for keys compared by `==`: assigning an existing
/// key keeps its position and replaces the value.
pub fn dict_set<K, V>(entries: &mut Vec<(K, V)>, key: K, value: V, same: impl Fn(&K, &K) -> bool) {
    if let Some(slot) = entries.iter_mut().find(|(existing, _)| same(existing, &key)) {
        slot.1 = value;
    } else {
        entries.push((key, value));
    }
}

/// `{**a, **b}` where `a` must be a mapping.
pub fn merge_mapping(base: &Value, extra: &Map<String, Value>) -> Result<Map<String, Value>, PyErr> {
    let Value::Object(base) = base else {
        return Err(PyErr::type_error(format!("'{}' object is not a mapping", type_name(base))));
    };
    let mut merged = base.clone();
    for (key, value) in extra {
        merged.insert(key.clone(), value.clone());
    }
    Ok(merged)
}

/// `d.update(other)` for a dict `d`.
pub fn dict_update(target: &mut Map<String, Value>, other: &Value) -> Result<(), PyErr> {
    match other {
        Value::Object(map) => {
            for (key, value) in map {
                target.insert(key.clone(), value.clone());
            }
            Ok(())
        }
        Value::Array(_) | Value::String(_) => {
            for (index, element) in iterate(other)?.into_iter().enumerate() {
                let pair = match &element {
                    Value::Array(_) | Value::String(_) | Value::Object(_) => iterate(&element)?,
                    _ => {
                        return Err(PyErr::type_error(format!(
                            "cannot convert dictionary update sequence element #{index} to a sequence"
                        )))
                    }
                };
                if pair.len() != 2 {
                    return Err(PyErr::new(
                        "ValueError",
                        format!("dictionary update sequence element #{index} has length {}; 2 is required", pair.len()),
                    ));
                }
                target.insert(str_of(&pair[0]), pair[1].clone());
            }
            Ok(())
        }
        other => Err(PyErr::type_error(format!("'{}' object is not iterable", type_name(other)))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn repr_matches_python() {
        assert_eq!(repr(&json!({"a": [1, 2.5, true, null, "x"]})), "{'a': [1, 2.5, True, None, 'x']}");
        assert_eq!(repr_str("it's"), "\"it's\"");
        assert_eq!(repr_str("both ' and \""), "'both \\' and \"'");
        assert_eq!(repr_str("tab\tnl\n\u{7}\u{a0}é"), "'tab\\tnl\\n\\x07\\xa0é'");
        assert_eq!(str_of(&json!("plain")), "plain");
    }

    #[test]
    fn float_repr_matches_python() {
        for (value, text) in [
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (12.5, "12.5"),
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (1e-5, "1e-05"),
            (0.0001, "0.0001"),
            (1.5e300, "1.5e+300"),
            (1760000000.5, "1760000000.5"),
            (0.1, "0.1"),
            (-2.5e-7, "-2.5e-07"),
            (123456789012345680.0, "1.2345678901234568e+17"),
        ] {
            assert_eq!(float_repr(value), text, "{value}");
        }
    }

    #[test]
    fn dumps_matches_python_indent_one_and_default_separators() {
        let value = json!({"a": [1, {"b": []}], "c": {}, "d": "ü\u{2028}\"", "e": 1e16});
        assert_eq!(
            dumps(&value, true),
            "{\n \"a\": [\n  1,\n  {\n   \"b\": []\n  }\n ],\n \"c\": {},\n \"d\": \"ü\u{2028}\\\"\",\n \"e\": 1e+16\n}"
        );
        assert_eq!(
            dumps(&value, false),
            "{\"a\": [1, {\"b\": []}], \"c\": {}, \"d\": \"ü\u{2028}\\\"\", \"e\": 1e+16}"
        );
    }

    #[test]
    fn int_matches_python() {
        assert_eq!(int_of(&json!(" 12 ")).unwrap(), "12");
        assert_eq!(int_of(&json!("1_000")).unwrap(), "1000");
        assert_eq!(int_of(&json!("-007")).unwrap(), "-7");
        assert_eq!(int_of(&json!(2.9)).unwrap(), "2");
        assert_eq!(int_of(&json!(-2.9)).unwrap(), "-2");
        assert_eq!(int_of(&json!(true)).unwrap(), "1");
        assert_eq!(int_of(&json!("abc")).unwrap_err().message, "invalid literal for int() with base 10: 'abc'");
        assert_eq!(
            int_of(&json!([1])).unwrap_err().message,
            "int() argument must be a string, a bytes-like object or a real number, not 'list'"
        );
    }

    #[test]
    fn quoting_matches_urllib() {
        assert_eq!(quote("g/1 ü~*"), "g%2F1%20%C3%BC~%2A");
        assert_eq!(
            urlencode(&[
                ("limit".into(), json!(5)),
                ("actor".into(), json!("key:mcp a")),
                ("l".into(), json!([true, null]))
            ]),
            "limit=5&actor=key%3Amcp+a&l=true&l="
        );
    }

    #[test]
    fn python_errors_carry_python_messages() {
        assert_eq!(getitem(&json!({}), "id").unwrap_err().message, "'id'");
        assert_eq!(getitem(&json!("ab"), "id").unwrap_err().message, "string indices must be integers, not 'str'");
        assert_eq!(get(&json!([1]), "x").unwrap_err().message, "'list' object has no attribute 'get'");
        assert_eq!(iterate(&json!(5)).unwrap_err().message, "'int' object is not iterable");
        assert_eq!(contains(&json!(true), "x").unwrap_err().message, "argument of type 'bool' is not iterable");
        assert_eq!(strip("\u{1c} x \u{a0}"), "x");
        assert!(eq(&json!(1), &json!(1.0)) && eq(&json!(true), &json!(1)) && !eq(&json!("1"), &json!(1)));
    }
}
