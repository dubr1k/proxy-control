//! JSON byte formatting shared by managers and host tools.
//!
//! Format selectors stay with their consumers: whitespace, Unicode escaping, key order and
//! number rendering are persisted/wire contracts, not interchangeable defaults. In particular,
//! AWG uses serde's number text, while the older managers retain Rust's shortest-digit tie
//! rounding and the host uses Python's even-digit rounding. Values are borrowed throughout.

use std::fmt::Write as _;

use serde_json::{Map, Number, Value};

/// The shortest-digit selection used before applying Python's notation thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloatMode {
    /// Python's `repr(float)`, including even-digit rounding on an exact shortest-digit tie.
    Python,
    /// The legacy manager format: Rust's shortest digits, with Python's notation thresholds.
    RustShortest,
}

/// Number text is part of each consumer's byte contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumberMode {
    /// `serde_json::Number`'s display representation (the AWG manager's existing format).
    Serde,
    /// Integer text unchanged; floats use the selected Python-style formatter.
    Python(FloatMode),
}

/// Explicit `json.dumps` formatting choices, plus the consumer's number representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// `indent=` (`None` = one line; `Some(0)` still inserts newlines).
    pub indent: Option<usize>,
    /// `separators=(item, key)`; `None` selects Python's defaults for the indent.
    pub separators: Option<(&'static str, &'static str)>,
    /// Sort object keys by code point instead of retaining the map's iteration order.
    pub sort_keys: bool,
    /// Escape everything outside printable ASCII, including DEL and surrogate pairs.
    pub ensure_ascii: bool,
    pub numbers: NumberMode,
}

impl Options {
    fn effective_separators(&self) -> (&'static str, &'static str) {
        match (self.separators, self.indent) {
            (Some(separators), _) => separators,
            (None, None) => (", ", ": "),
            (None, Some(_)) => (",", ": "),
        }
    }
}

/// Serialize a borrowed JSON value without converting or copying its tree.
pub fn dumps(value: &Value, options: &Options) -> String {
    let mut out = String::new();
    let (item, key) = options.effective_separators();
    Writer { options, item, key }.value(&mut out, value, 0);
    out
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
            Value::Number(number) => write_number(out, number, self.options.numbers),
            Value::String(text) => write_string(out, text, self.options.ensure_ascii),
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
            Value::Object(map) => self.object(out, map, level),
        }
    }

    fn object(&self, out: &mut String, map: &Map<String, Value>, level: usize) {
        if map.is_empty() {
            out.push_str("{}");
            return;
        }
        out.push('{');
        if self.options.sort_keys {
            let mut entries: Vec<_> = map.iter().collect();
            // UTF-8 byte order is code-point order, which is how Python sorts `str`.
            entries.sort_by(|a, b| a.0.cmp(b.0));
            self.entries(out, entries.into_iter(), level);
        } else {
            self.entries(out, map.iter(), level);
        }
        self.newline(out, level);
        out.push('}');
    }

    fn entries<'a>(&self, out: &mut String, entries: impl Iterator<Item = (&'a String, &'a Value)>, level: usize) {
        for (index, (key, item)) in entries.enumerate() {
            if index > 0 {
                out.push_str(self.item);
            }
            self.newline(out, level + 1);
            write_string(out, key, self.options.ensure_ascii);
            out.push_str(self.key);
            self.value(out, item, level + 1);
        }
    }

    fn newline(&self, out: &mut String, level: usize) {
        if let Some(indent) = self.options.indent {
            out.push('\n');
            out.extend(std::iter::repeat_n(' ', indent * level));
        }
    }
}

fn write_string(out: &mut String, text: &str, ensure_ascii: bool) {
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
            _ if ensure_ascii => {
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

/// Number text for consumers that also use JSON numbers in Python-style container reprs.
pub fn number_repr(number: &Number, mode: NumberMode) -> String {
    let mut out = String::new();
    write_number(&mut out, number, mode);
    out
}

fn write_number(out: &mut String, number: &Number, mode: NumberMode) {
    let NumberMode::Python(float_mode) = mode else {
        let _ = write!(out, "{number}");
        return;
    };
    if let Some(value) = number.as_i64() {
        let _ = write!(out, "{value}");
    } else if let Some(value) = number.as_u64() {
        let _ = write!(out, "{value}");
    } else if let Some(value) = number.as_f64() {
        out.push_str(&float_repr(value, float_mode));
    } else {
        // All serde_json numbers without arbitrary_precision fit one of the cases above.
        out.push_str("null");
    }
}

/// Python-style float notation, retaining the requested historical shortest-digit behavior.
/// Non-finite values use JSON's `NaN`/`Infinity` spellings, as the existing host/managers did.
pub fn float_repr(value: f64, mode: FloatMode) -> String {
    if value.is_nan() {
        return "NaN".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    let sign = if value.is_sign_negative() { "-" } else { "" };
    let (digits, exponent) = match mode {
        FloatMode::Python => shortest_digits(value.abs()),
        FloatMode::RustShortest => split_scientific(&format!("{:e}", value.abs())),
    };
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

/// Rust's shortest round-tripping digits agree with Python's `dtoa` mode 0 except on an exact
/// tie between two shortest candidates, where Python takes the even digit.
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
    let even = if (lower.as_bytes()[length - 1] - b'0') % 2 == 0 {
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
    use super::*;
    use serde_json::json;

    #[test]
    fn historical_number_modes_keep_distinct_persisted_bytes() {
        let options = Options {
            indent: None,
            separators: Some((",", ":")),
            sort_keys: true,
            ensure_ascii: true,
            numbers: NumberMode::Python(FloatMode::Python),
        };
        // An exact shortest-digit tie is deliberately different in the older managers.
        let tie = json!(789296645419347.25);
        assert_eq!(dumps(&tie, &options), "789296645419347.2");
        assert_eq!(
            dumps(&tie, &Options { numbers: NumberMode::Python(FloatMode::RustShortest), ..options }),
            "789296645419347.3"
        );
    }
}
