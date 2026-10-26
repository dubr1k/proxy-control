//! Python-compatible JSON bytes for the host's state files.
//!
//! The installer journal, the plan digest and the version-agent state are compared and hashed
//! as bytes, so the writers reproduce `json.dumps` exactly. The three host forms:
//!
//! | Writer | Python | Used for |
//! |---|---|---|
//! | [`canonical`] | `json.dumps(v, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True)` | `plan.json`, the plan digest, runtime-v2 ids |
//! | [`pretty2`] | `json.dumps(v, allow_nan=False, ensure_ascii=False, indent=2, sort_keys=True) + "\n"` | `state.json`, `ownership.json`, `report.json`, the installer's agent seed, `release.json` |
//! | [`pretty2_ascii_nonl`] | `json.dumps(v, indent=2, sort_keys=True)` (ASCII, **no** newline) | the version-agent's `state.json` |
//! | [`pretty2_ascii`] | `json.dumps(v, indent=2, sort_keys=True) + "\n"` (ASCII) | the installer's seed of that `state.json` |
//!
//! Values are [`serde_json::Value`] **without** `preserve_order`: every host writer sorts keys,
//! and the map is a `BTreeMap`, whose UTF-8 byte order is Python's code-point order. Limits of
//! that model: integers must fit `i64`/`u64` (larger ones are refused by [`loads`], where Python
//! would keep them), `NaN`/`Infinity` cannot be represented (Python wrote them only without
//! `allow_nan=False`; [`loads`] refuses them), strings cannot hold lone surrogates.

use std::fmt::Write as _;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

/// `json.dumps` keyword arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// `indent=` (`None` = one line).
    pub indent: Option<usize>,
    /// `separators=(item, key)`; `None` = Python's default for the indent.
    pub separators: Option<(&'static str, &'static str)>,
    /// `sort_keys=`.
    pub sort_keys: bool,
    /// `ensure_ascii=`.
    pub ensure_ascii: bool,
}

impl Options {
    /// The installer's `_canonical_json`.
    pub const CANONICAL: Options =
        Options { indent: None, separators: Some((",", ":")), sort_keys: true, ensure_ascii: false };
    /// The installer's `_pretty_json` (without its trailing newline).
    pub const PRETTY2: Options = Options { indent: Some(2), separators: None, sort_keys: true, ensure_ascii: false };
    /// The version-agent's state writer.
    pub const PRETTY2_ASCII: Options =
        Options { indent: Some(2), separators: None, sort_keys: true, ensure_ascii: true };

    fn effective_separators(&self) -> (&'static str, &'static str) {
        match (self.separators, self.indent) {
            (Some(separators), _) => separators,
            (None, None) => (", ", ": "),
            (None, Some(_)) => (",", ": "),
        }
    }
}

/// `json.dumps(value, **options)`.
pub fn dumps(value: &Value, options: &Options) -> String {
    let mut out = String::new();
    let (item, key) = options.effective_separators();
    Writer { options, item, key }.value(&mut out, value, 0);
    out
}

/// Compact, sorted, raw UTF-8: the bytes behind `plan.json` and every plan digest.
pub fn canonical(value: &Value) -> String {
    dumps(value, &Options::CANONICAL)
}

/// Indent 2, sorted, raw UTF-8, trailing `\n`: the installer journal files.
pub fn pretty2(value: &Value) -> String {
    let mut out = dumps(value, &Options::PRETTY2);
    out.push('\n');
    out
}

/// Indent 2, sorted, ASCII-escaped, **no** trailing newline: the version-agent's `state.json`.
pub fn pretty2_ascii_nonl(value: &Value) -> String {
    dumps(value, &Options::PRETTY2_ASCII)
}

/// Indent 2, sorted, ASCII-escaped, trailing `\n`: the installer's seed of the agent's
/// `state.json` (`installer/adapters/version_agent.py:476`).
pub fn pretty2_ascii(value: &Value) -> String {
    let mut out = dumps(value, &Options::PRETTY2_ASCII);
    out.push('\n');
    out
}

/// SHA-256 of [`canonical`] as lowercase hex (`sha256(_canonical_json(v))`).
pub fn canonical_digest(value: &Value) -> String {
    crate::fs::sha256_hex(canonical(value).as_bytes())
}

/// Why JSON text was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonError {
    /// The bytes are not UTF-8 or not JSON (including `NaN`, `Infinity`, lone surrogates and
    /// integers outside `i64`/`u64`).
    Invalid(String),
    /// [`loads_strict`] met a key twice in one object (`duplicate JSON key: <k>`).
    DuplicateKey(String),
}

impl std::fmt::Display for JsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JsonError::Invalid(detail) => write!(f, "invalid JSON: {detail}"),
            JsonError::DuplicateKey(key) => write!(f, "duplicate JSON key: {key}"),
        }
    }
}

impl std::error::Error for JsonError {}

/// `json.loads(data)` for host state: any formatting, duplicate keys allowed (the last wins).
pub fn loads(data: &[u8]) -> Result<Value, JsonError> {
    parse(data, false)
}

/// `json.loads(data, object_pairs_hook=<reject duplicates>, parse_constant=<reject>)`: the
/// release manifest's reader.
pub fn loads_strict(data: &[u8]) -> Result<Value, JsonError> {
    parse(data, true)
}

fn parse(data: &[u8], reject_duplicates: bool) -> Result<Value, JsonError> {
    let text = std::str::from_utf8(data).map_err(|err| JsonError::Invalid(err.to_string()))?;
    check_integer_range(text)?;
    // serde_json's nesting limit (128) stands in for Python's `RecursionError`.
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value = ValueSeed { reject_duplicates }.deserialize(&mut deserializer).map_err(|err| {
        let message = err.to_string();
        match message.strip_prefix(DUPLICATE_MARKER) {
            Some(rest) => JsonError::DuplicateKey(rest.split(" at line ").next().unwrap_or(rest).to_string()),
            None => JsonError::Invalid(message),
        }
    })?;
    deserializer.end().map_err(|err| JsonError::Invalid(err.to_string()))?;
    Ok(value)
}

const DUPLICATE_MARKER: &str = "\u{0}duplicate:";

/// Refuses an integer literal outside `i64`/`u64`: serde_json would read it as a float and a
/// rewrite would change its bytes (Python keeps arbitrary-precision ints).
fn check_integer_range(text: &str) -> Result<(), JsonError> {
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut in_string = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            match byte {
                b'\\' => index += 1,
                b'"' => in_string = false,
                _ => {}
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
            index += 1;
            continue;
        }
        if byte == b'-' || byte.is_ascii_digit() {
            let start = index;
            index += 1;
            while index < bytes.len() && matches!(bytes[index], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-') {
                index += 1;
            }
            let token = &text[start..index];
            let integral = !token.contains(['.', 'e', 'E']);
            if integral && token.parse::<i64>().is_err() && token.parse::<u64>().is_err() && token != "-" {
                return Err(JsonError::Invalid(format!("integer out of range: {token}")));
            }
            continue;
        }
        index += 1;
    }
    Ok(())
}

/// Builds a [`Value`] like serde_json does, but refuses integers that do not fit 64 bits (serde
/// would silently turn them into floats and change the bytes on rewrite) and, when asked,
/// duplicate keys.
#[derive(Clone, Copy)]
struct ValueSeed {
    reject_duplicates: bool,
}

impl<'de> DeserializeSeed<'de> for ValueSeed {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for ValueSeed {
    type Value = Value;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v).map(Value::Number).ok_or_else(|| E::custom("number is not finite"))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(self)? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
        let mut map = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            let value = access.next_value_seed(self)?;
            if map.insert(key.clone(), value).is_some() && self.reject_duplicates {
                return Err(de::Error::custom(format!("{DUPLICATE_MARKER}{key}")));
            }
        }
        Ok(Value::Object(map))
    }
}

struct Writer<'a> {
    options: &'a Options,
    item: &'static str,
    key: &'static str,
}

impl Writer<'_> {
    fn value(&self, out: &mut String, value: &Value, level: usize) {
        match value {
            Value::Null => out.push_str("null"),
            Value::Bool(true) => out.push_str("true"),
            Value::Bool(false) => out.push_str("false"),
            Value::Number(number) => number_text(out, number),
            Value::String(text) => self.string(out, text),
            Value::Array(items) => {
                if items.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push_str(self.item);
                    }
                    self.newline(out, level + 1);
                    self.value(out, item, level + 1);
                }
                self.newline(out, level);
                out.push(']');
            }
            Value::Object(map) => {
                if map.is_empty() {
                    out.push_str("{}");
                    return;
                }
                let mut entries: Vec<(&String, &Value)> = map.iter().collect();
                if self.options.sort_keys {
                    // UTF-8 byte order is code-point order, which is how Python sorts `str`.
                    entries.sort_by(|a, b| a.0.cmp(b.0));
                }
                out.push('{');
                for (index, (key, item)) in entries.into_iter().enumerate() {
                    if index > 0 {
                        out.push_str(self.item);
                    }
                    self.newline(out, level + 1);
                    self.string(out, key);
                    out.push_str(self.key);
                    self.value(out, item, level + 1);
                }
                self.newline(out, level);
                out.push('}');
            }
        }
    }

    fn newline(&self, out: &mut String, level: usize) {
        if let Some(indent) = self.options.indent {
            out.push('\n');
            out.extend(std::iter::repeat_n(' ', indent * level));
        }
    }

    fn string(&self, out: &mut String, text: &str) {
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
                '\0'..='\u{1f}' => {
                    let _ = write!(out, "\\u{:04x}", ch as u32);
                }
                ' '..='~' => out.push(ch),
                _ if self.options.ensure_ascii => {
                    let mut units = [0u16; 2];
                    for unit in ch.encode_utf16(&mut units) {
                        let _ = write!(out, "\\u{unit:04x}");
                    }
                }
                _ => out.push(ch),
            }
        }
        out.push('"');
    }
}

fn number_text(out: &mut String, number: &Number) {
    if let Some(value) = number.as_i64() {
        let _ = write!(out, "{value}");
    } else if let Some(value) = number.as_u64() {
        let _ = write!(out, "{value}");
    } else if let Some(value) = number.as_f64() {
        out.push_str(&float_repr(value));
    } else {
        out.push_str("null");
    }
}

/// Python's `repr(float)`, which `json.dumps` writes for a finite float: the shortest digits
/// that round-trip, fixed notation for decimal exponents −4 ≤ e < 16 (always with a fraction,
/// `1.0`), otherwise `d.ddde±XX` (`1e-05`, `1e+16`).
pub fn float_repr(value: f64) -> String {
    if value.is_nan() {
        return "NaN".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    let sign = if value.is_sign_negative() { "-" } else { "" };
    let (digits, exponent) = shortest_digits(value.abs());
    let decpt = exponent + 1;
    let mut out = String::from(sign);
    if -4 < decpt && decpt <= 16 {
        let len = digits.len() as i32;
        if decpt <= 0 {
            out.push_str("0.");
            out.extend(std::iter::repeat_n('0', (-decpt) as usize));
            out.push_str(&digits);
        } else if decpt >= len {
            out.push_str(&digits);
            out.extend(std::iter::repeat_n('0', (decpt - len) as usize));
            out.push_str(".0");
        } else {
            out.push_str(&digits[..decpt as usize]);
            out.push('.');
            out.push_str(&digits[decpt as usize..]);
        }
    } else {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        out.push(if exponent < 0 { '-' } else { '+' });
        let _ = write!(out, "{:02}", exponent.abs());
    }
    out
}

fn split_scientific(text: &str) -> (String, i32) {
    let (mantissa, exponent) = text.split_once('e').expect("`{:e}` always has an exponent");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    (digits, exponent.parse().expect("`{:e}` exponent is an integer"))
}

/// The shortest round-tripping digits as David Gay's `dtoa` mode 0 picks them for Python: Rust's
/// `{:e}` agrees except on an exact tie between two shortest candidates, where Python takes the
/// even digit.
fn shortest_digits(value: f64) -> (String, i32) {
    let (digits, exponent) = split_scientific(&format!("{value:e}"));
    if digits.bytes().all(|b| b == b'0') {
        return ("0".into(), 0);
    }
    let length = digits.len();
    let precision = length + 1;
    let (probe, probe_exponent) = split_scientific(&format!("{value:.precision$e}"));
    if !probe.ends_with("50") {
        return (digits, exponent);
    }
    let (exact, exact_exponent) = split_scientific(&format!("{value:.1100e}"));
    let exact = exact.trim_end_matches('0');
    if exact.len() != length + 1 || !exact.ends_with('5') || exact_exponent != probe_exponent {
        return (digits, exponent);
    }
    let lower = &exact[..length];
    let even = if (lower.as_bytes()[length - 1] - b'0').is_multiple_of(2) {
        (lower.to_string(), exact_exponent)
    } else {
        increment(lower, exact_exponent)
    };
    let even_digits = even.0.trim_end_matches('0').to_string();
    let candidate = if even_digits.len() > 1 {
        format!("{}.{}e{}", &even_digits[..1], &even_digits[1..], even.1)
    } else {
        format!("{even_digits}e{}", even.1)
    };
    if candidate.parse::<f64>().ok() == Some(value) {
        (even_digits, even.1)
    } else {
        (digits, exponent)
    }
}

fn increment(digits: &str, exponent: i32) -> (String, i32) {
    let mut bytes = digits.as_bytes().to_vec();
    for byte in bytes.iter_mut().rev() {
        if *byte == b'9' {
            *byte = b'0';
        } else {
            *byte += 1;
            return (String::from_utf8(bytes).expect("ASCII digits"), exponent);
        }
    }
    bytes.insert(0, b'1');
    bytes.pop();
    (String::from_utf8(bytes).expect("ASCII digits"), exponent + 1)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn the_three_host_forms() {
        let value = json!({"b": [1, {}], "a": "é", "c": []});
        assert_eq!(canonical(&value), "{\"a\":\"é\",\"b\":[1,{}],\"c\":[]}");
        assert_eq!(pretty2(&value), "{\n  \"a\": \"é\",\n  \"b\": [\n    1,\n    {}\n  ],\n  \"c\": []\n}\n");
        assert_eq!(
            pretty2_ascii_nonl(&value),
            "{\n  \"a\": \"\\u00e9\",\n  \"b\": [\n    1,\n    {}\n  ],\n  \"c\": []\n}"
        );
        assert_eq!(pretty2(&json!({})), "{}\n");
    }

    #[test]
    fn strings_escape_like_python() {
        let text = json!("\"\\\u{8}\u{c}\n\r\t\u{0}\u{1f}\u{7f}\u{80}é😀");
        assert_eq!(canonical(&text), "\"\\\"\\\\\\b\\f\\n\\r\\t\\u0000\\u001f\u{7f}\u{80}é😀\"");
        assert_eq!(
            pretty2_ascii_nonl(&text),
            "\"\\\"\\\\\\b\\f\\n\\r\\t\\u0000\\u001f\\u007f\\u0080\\u00e9\\ud83d\\ude00\""
        );
    }

    #[test]
    fn floats_follow_repr() {
        for (value, text) in [
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (0.1, "0.1"),
            (1e-05, "1e-05"),
            (0.0001, "0.0001"),
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (5e-324, "5e-324"),
            (0.30000000000000004, "0.30000000000000004"),
        ] {
            assert_eq!(float_repr(value), text, "{value}");
        }
        assert_eq!(float_repr("789296645419347.25".parse().unwrap()), "789296645419347.2");
    }

    #[test]
    fn loads_keeps_the_last_duplicate_and_strict_refuses_it() {
        assert_eq!(loads(br#"{"a":1,"a":2}"#).unwrap(), json!({"a": 2}));
        assert_eq!(loads_strict(br#"{"a":1,"a":2}"#), Err(JsonError::DuplicateKey("a".into())));
        assert_eq!(loads_strict(br#"{"a":1,"b":{"c":1,"c":2},"a":3}"#), Err(JsonError::DuplicateKey("c".into())));
        assert!(matches!(loads(b"NaN"), Err(JsonError::Invalid(_))));
        assert!(matches!(loads(b"{\"a\": Infinity}"), Err(JsonError::Invalid(_))));
        assert!(matches!(loads(b"\xff"), Err(JsonError::Invalid(_))));
        assert!(matches!(loads(b"{} x"), Err(JsonError::Invalid(_))));
        assert!(matches!(loads(b"\"\\ud800\""), Err(JsonError::Invalid(_))));
    }

    #[test]
    fn loads_refuses_integers_python_would_keep_but_rewrite_would_change() {
        assert_eq!(loads(b"18446744073709551615").unwrap(), json!(u64::MAX));
        assert_eq!(loads(b"-9223372036854775808").unwrap(), json!(i64::MIN));
        // serde_json would hand these over as floats and a rewrite would print `1.8446744073709552e+19`.
        assert!(loads(b"18446744073709551616").is_err());
        assert!(loads(b"[1, -9223372036854775809]").is_err());
        assert!(loads(b"[\"18446744073709551616\", 1e400]").is_err());
        assert_eq!(loads(b"[\"18446744073709551616\", 1.5e3]").unwrap(), json!(["18446744073709551616", 1500.0]));
    }

    #[test]
    fn rewrite_keeps_bytes_for_any_formatting() {
        let compact = br#"{"z":[1,2.5,"\u00e9"],"a":{"k":null,"t":true}}"#;
        let value = loads(compact).unwrap();
        assert_eq!(canonical(&value), "{\"a\":{\"k\":null,\"t\":true},\"z\":[1,2.5,\"é\"]}");
        assert_eq!(canonical_digest(&json!({})), crate::fs::sha256_hex(b"{}"));
    }
}
