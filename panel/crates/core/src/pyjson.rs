//! Python-compatible JSON text.
//!
//! The panel hashes, compares and encrypts JSON text (the AES-GCM AAD, fleet generation digests,
//! the subscription ETag, `fleet_commands.payload_json`, the audit `detail_json`, the client-list
//! cursor), so the bytes must be exactly what Python writes. [`dumps`] reproduces `json.dumps` with
//! any combination of `separators`, `indent`, `sort_keys` and `ensure_ascii`; [`pydantic`]
//! reproduces pydantic-core's `to_json`/`model_dump_json` (compact, raw UTF-8, its own float form).
//!
//! Values are [`serde_json::Value`] with the `preserve_order` feature, so objects keep insertion
//! order like Python dicts. Limits of that model, all outside what the panel stores:
//! - integers must fit `i64`/`u64` (Python ints are unbounded);
//! - `NaN`/`Infinity` cannot be represented (`serde_json` turns a non-finite `f64` into `null`;
//!   Python would write `NaN` or, with `allow_nan=False`, raise) — reject them before building
//!   the value;
//! - strings cannot hold lone surrogates.

use std::fmt::Write as _;

use serde_json::Value;

/// `json.dumps` keyword arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// `indent=` (`None` = single line). `Some(0)` still breaks lines, like Python.
    pub indent: Option<usize>,
    /// `separators=(item, key)`; `None` = Python's default, which depends on `indent`:
    /// `(", ", ": ")` without indent, `(",", ": ")` with it.
    pub separators: Option<(&'static str, &'static str)>,
    /// `sort_keys=` — keys ordered by code point (Python's `str` order).
    pub sort_keys: bool,
    /// `ensure_ascii=` — escape everything outside printable ASCII as lowercase `\uXXXX`
    /// (surrogate pairs above the BMP).
    pub ensure_ascii: bool,
}

impl Default for Options {
    /// `json.dumps(value)` with no keyword arguments.
    fn default() -> Self {
        Self { indent: None, separators: None, sort_keys: false, ensure_ascii: true }
    }
}

impl Options {
    /// `separators=(",", ":")`.
    pub const COMPACT: Options =
        Options { indent: None, separators: Some((",", ":")), sort_keys: false, ensure_ascii: true };
    /// `sort_keys=True, separators=(",", ":")` (ASCII) — the panel's canonical form.
    pub const CANONICAL: Options =
        Options { indent: None, separators: Some((",", ":")), sort_keys: true, ensure_ascii: true };
    /// `sort_keys=True` with the default separators.
    pub const SORTED: Options = Options { indent: None, separators: None, sort_keys: true, ensure_ascii: true };
    /// `ensure_ascii=False, separators=(",", ":")` — also what Starlette's `JSONResponse` renders.
    pub const COMPACT_UTF8: Options =
        Options { indent: None, separators: Some((",", ":")), sort_keys: false, ensure_ascii: false };

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
    let writer = Writer { options, item, key };
    writer.value(&mut out, value, 0);
    out
}

/// `json.dumps(value)`.
pub fn dumps_default(value: &Value) -> String {
    dumps(value, &Options::default())
}

/// `json.dumps(value, separators=(",", ":"))`.
pub fn compact(value: &Value) -> String {
    dumps(value, &Options::COMPACT)
}

/// `json.dumps(value, sort_keys=True, separators=(",", ":"))` (ASCII).
pub fn canonical(value: &Value) -> String {
    dumps(value, &Options::CANONICAL)
}

/// `json.dumps(value, sort_keys=True)`.
pub fn sorted(value: &Value) -> String {
    dumps(value, &Options::SORTED)
}

/// `json.dumps(value, ensure_ascii=False, separators=(",", ":"))` — the body bytes of a Starlette
/// `JSONResponse`.
pub fn compact_utf8(value: &Value) -> String {
    dumps(value, &Options::COMPACT_UTF8)
}

/// `pydantic_core.to_json(value)` / `Model.model_dump_json()`: compact, raw UTF-8 (only `"`, `\`
/// and C0 controls escaped), insertion order, pydantic's float form (see [`pydantic_float`]).
pub fn pydantic(value: &Value) -> String {
    let mut out = String::new();
    pydantic_value(&mut out, value);
    out
}

/// Python's `repr(float)` (also what `json.dumps` writes for a float): the shortest digits that
/// round-trip, fixed notation for exponents −4 ≤ e < 16 (always with a fraction, `1.0`), otherwise
/// `d.ddde±XX` with at least two exponent digits (`1e-05`, `1e+16`). Non-finite values give
/// `inf`, `-inf`, `nan` (`repr`; `json.dumps` would write `Infinity`/`NaN`).
pub fn float_repr(value: f64) -> String {
    format_float(value, FloatStyle::Python)
}

/// pydantic-core's float form: like [`float_repr`] but fixed notation already from exponent −5
/// (`0.00001`) and exponents without zero padding (`1e-7`, `1e+16`).
pub fn pydantic_float(value: f64) -> String {
    format_float(value, FloatStyle::Pydantic)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FloatStyle {
    Python,
    Pydantic,
}

fn format_float(value: f64, style: FloatStyle) -> String {
    if value.is_nan() {
        return "nan".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "inf".into() } else { "-inf".into() };
    }
    let sign = if value.is_sign_negative() { "-" } else { "" };
    let (digits, exponent) = shortest_digits(value.abs());
    // Python's `decpt`: the value is 0.DIGITS × 10^decpt.
    let decpt = exponent + 1;
    let fixed = match style {
        FloatStyle::Python => -4 < decpt && decpt <= 16,
        FloatStyle::Pydantic => -5 < decpt && decpt <= 16,
    };
    let mut out = String::from(sign);
    if fixed {
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
        match style {
            FloatStyle::Python => {
                let _ = write!(out, "{:02}", exponent.abs());
            }
            FloatStyle::Pydantic => {
                let _ = write!(out, "{}", exponent.abs());
            }
        }
    }
    out
}

/// Splits `{:e}` output into its significant digits and decimal exponent (value = d.ddd × 10^exp).
fn split_scientific(text: &str) -> (String, i32) {
    let (mantissa, exponent) = text.split_once('e').expect("`{:e}` always has an exponent");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    (digits, exponent.parse().expect("`{:e}` exponent is an integer"))
}

/// The shortest digits that round-trip, as David Gay's `dtoa` (mode 0) picks them for Python.
///
/// Rust's `{:e}` already gives the shortest round-tripping digits closest to the value; the one
/// difference is an exact tie — the binary value lies exactly halfway between two shortest
/// candidates (`789296645419347.25` → `…347.2` or `…347.3`). Rust rounds such a tie up, Python
/// to the even digit.
fn shortest_digits(value: f64) -> (String, i32) {
    let (digits, exponent) = split_scientific(&format!("{value:e}"));
    if digits.bytes().all(|b| b == b'0') {
        return ("0".into(), 0);
    }
    let length = digits.len();
    // A tie needs the exact value to have exactly `length + 1` significant digits ending in 5;
    // `length + 2` correctly rounded digits show that cheaply (…50), the exact expansion confirms.
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
    let even = if (lower.as_bytes()[length - 1] - b'0') % 2 == 0 {
        (lower.to_string(), exact_exponent)
    } else {
        increment(lower, exact_exponent)
    };
    let even_digits = even.0.trim_end_matches('0').to_string();
    let reparsed: f64 = format!("{}.{}e{}", &even_digits[..1], &even_digits[1..], even.1).parse().unwrap_or(f64::NAN);
    if reparsed == value {
        (even_digits, even.1)
    } else {
        (digits, exponent)
    }
}

/// Adds one unit in the last place to a digit string (value = d.ddd × 10^exponent).
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
            Value::Number(number) => number_text(out, number, FloatStyle::Python),
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
        if self.options.ensure_ascii {
            ascii_string(out, text);
        } else {
            utf8_string(out, text);
        }
    }
}

fn number_text(out: &mut String, number: &serde_json::Number, style: FloatStyle) {
    if let Some(value) = number.as_i64() {
        let _ = write!(out, "{value}");
    } else if let Some(value) = number.as_u64() {
        let _ = write!(out, "{value}");
    } else if let Some(value) = number.as_f64() {
        out.push_str(&format_float(value, style));
    } else {
        out.push_str("null");
    }
}

/// `ensure_ascii=True`: Python's `ESCAPE_ASCII` — everything outside `' '..='~'` is escaped.
fn ascii_string(out: &mut String, text: &str) {
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
            ' '..='~' => out.push(ch),
            _ => {
                let mut units = [0u16; 2];
                for unit in ch.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
}

/// `ensure_ascii=False`: only `"`, `\` and C0 controls are escaped (DEL and above go out raw).
fn utf8_string(out: &mut String, text: &str) {
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
            _ => out.push(ch),
        }
    }
    out.push('"');
}

fn pydantic_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => number_text(out, number, FloatStyle::Pydantic),
        Value::String(text) => utf8_string(out, text),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                pydantic_value(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (index, (key, item)) in map.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                utf8_string(out, key);
                out.push(':');
                pydantic_value(out, item);
            }
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn float_repr_matches_python_for_the_classic_cases() {
        for (value, text) in [
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (1.0, "1.0"),
            (0.1, "0.1"),
            (1e-05, "1e-05"),
            (0.0001, "0.0001"),
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (1.5e16, "1.5e+16"),
            (123456789.123, "123456789.123"),
            (5e-324, "5e-324"),
            (1e308, "1e+308"),
        ] {
            assert_eq!(float_repr(value), text, "{value}");
        }
        assert_eq!(pydantic_float(1e-05), "0.00001");
        assert_eq!(pydantic_float(1e-07), "1e-7");
        assert_eq!(pydantic_float(1e16), "1e+16");
        // An exact tie between two shortest candidates goes to the even digit, as in Python.
        let tie: f64 = "789296645419347.25".parse().unwrap();
        assert_eq!(float_repr(tie), "789296645419347.2");
        assert_eq!(float_repr(0.5), "0.5");
        assert_eq!(float_repr(9.5), "9.5");
    }

    #[test]
    fn default_separators_depend_on_indent() {
        let value = json!({"a": [1, 2], "b": {}});
        assert_eq!(dumps_default(&value), r#"{"a": [1, 2], "b": {}}"#);
        let indented = Options { indent: Some(1), ..Options::default() };
        assert_eq!(dumps(&value, &indented), "{\n \"a\": [\n  1,\n  2\n ],\n \"b\": {}\n}");
    }

    #[test]
    fn ensure_ascii_escapes_like_python() {
        assert_eq!(compact(&json!("é\u{7f}🙂\u{1}")), r#""\u00e9\u007f\ud83d\ude42\u0001""#);
        assert_eq!(compact_utf8(&json!("é\u{7f}🙂\u{1}")), "\"é\u{7f}🙂\\u0001\"");
    }

    #[test]
    fn canonical_sorts_by_code_point() {
        assert_eq!(canonical(&json!({"b": 1, "a": {"é": 2, "z": 3}})), r#"{"a":{"z":3,"\u00e9":2},"b":1}"#);
    }
}
