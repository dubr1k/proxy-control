//! Python 3.13's text semantics where Rust's standard library answers differently.
//!
//! The Unicode tables (`tables.rs`) are generated from the panel image's Python 3.13.5
//! (Unicode 15.1) by `tests/fixtures/generators/gen_pytext.py`; every function here is checked
//! against golden vectors recorded from the same interpreter (`tests/fixtures/pytext.json`).
//!
//! NFC/NFKC and `lower()` come from `unicode-normalization` and the standard library, whose Unicode
//! version is newer than 15.1: they agree with Python on every code point assigned in Unicode 15.1
//! (checked over all of them) and may differ only on characters assigned later.

mod ip;
mod tables;
mod url;

use std::fmt::{self, Write as _};

pub use ip::{ip_address, IpAddress};
pub use url::{urlsplit, SplitResult};

/// A `ValueError` with Python's message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyValueError(pub String);

impl fmt::Display for PyValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PyValueError {}

fn in_table(table: &[(u32, u32)], code: u32) -> bool {
    table
        .binary_search_by(|&(start, end)| {
            if end < code {
                std::cmp::Ordering::Less
            } else if start > code {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// `ch.isspace()` — the whitespace of `str.split()` and `str.strip()` (includes `\x1c`–`\x1f`,
/// `\x85`, `\xa0`; excludes `\u200b` and `\ufeff`).
pub fn is_space(ch: char) -> bool {
    in_table(tables::WHITESPACE, ch as u32)
}

/// `text.split()` with no arguments: runs of whitespace separate, no empty items.
pub fn split(text: &str) -> Vec<&str> {
    text.split(is_space).filter(|part| !part.is_empty()).collect()
}

/// `text.strip()` with no arguments.
pub fn strip(text: &str) -> &str {
    text.trim_matches(is_space)
}

/// `" ".join(text.split())` — collapse every whitespace run to one space and trim.
pub fn collapse_whitespace(text: &str) -> String {
    split(text).join(" ")
}

/// `ch.isprintable()`: false for categories Cc, Cf, Cs, Co, Cn, Zl, Zp and Zs except the space.
pub fn is_printable_char(ch: char) -> bool {
    !in_table(tables::NON_PRINTABLE, ch as u32)
}

/// `text.isprintable()` (true for the empty string).
pub fn is_printable(text: &str) -> bool {
    text.chars().all(is_printable_char)
}

/// `unicodedata.decimal(ch)` — the value of a decimal digit (category Nd), any script.
pub fn decimal(ch: char) -> Option<u32> {
    let code = ch as u32;
    let index = tables::DECIMAL.partition_point(|&(start, _)| start <= code);
    let (start, end) = *tables::DECIMAL.get(index.checked_sub(1)?)?;
    (code <= end).then_some(code - start)
}

/// `unicodedata.normalize("NFC", text)`.
pub fn nfc(text: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    text.nfc().collect()
}

/// `unicodedata.normalize("NFKC", text)`.
pub fn nfkc(text: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    text.nfkc().collect()
}

/// `text.lower()` (full case mapping, final sigma included).
pub fn lower(text: &str) -> String {
    text.to_lowercase()
}

/// `len(text)` — code points, not bytes.
pub fn len(text: &str) -> usize {
    text.chars().count()
}

/// `text[start:end]` with Python's index rules (negative indexes count from the end, out-of-range
/// indexes clamp, `start >= end` gives `""`); indexes are code points.
pub fn slice(text: &str, start: Option<isize>, end: Option<isize>) -> &str {
    let length = len(text) as isize;
    let clamp = |index: isize| -> usize {
        let index = if index < 0 { index + length } else { index };
        index.clamp(0, length) as usize
    };
    let start = start.map_or(0, clamp);
    let end = end.map_or(length as usize, clamp);
    if start >= end {
        return "";
    }
    let byte = |index: usize| text.char_indices().nth(index).map_or(text.len(), |(offset, _)| offset);
    &text[byte(start)..byte(end)]
}

/// `text[:limit]` — the first `limit` code points.
pub fn truncate(text: &str, limit: usize) -> &str {
    slice(text, None, Some(limit as isize))
}

/// `repr(text)`: single quotes unless the text holds `'` and no `"`; `\\`, the quote, `\t`, `\n`,
/// `\r` escaped; other C0 controls, DEL and non-printable characters as `\xhh`, `\uhhhh` or
/// `\Uhhhhhhhh`.
pub fn repr(text: &str) -> String {
    pc_common::pytext::repr_with_printable(text, is_printable_char)
}

/// What `int()`/`float()` see first: Unicode whitespace becomes `' '`, decimal digits of any script
/// become ASCII digits, and the text is cut at the first other non-ASCII character (marked `?`).
fn to_ascii_digits(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if (ch as u32) < 127 {
            out.push(ch);
        } else if is_space(ch) {
            out.push(' ');
        } else if let Some(value) = decimal(ch) {
            out.push(char::from(b'0' + value as u8));
        } else {
            out.push('?');
            break;
        }
    }
    out
}

fn is_ascii_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r')
}

/// `int(text)` (base 10): surrounding whitespace, a sign, `_` between digits and non-ASCII decimal
/// digits are accepted, like Python. Values outside `i64` are refused (Python's ints are unbounded)
/// with the message `int() value out of range: …`.
pub fn int_from_str(text: &str) -> Result<i64, PyValueError> {
    let invalid = || {
        let mut shown = repr(text);
        if len(&shown) > 200 {
            shown = truncate(&shown, 200).to_string();
        }
        PyValueError(format!("invalid literal for int() with base 10: {shown}"))
    };
    let ascii = to_ascii_digits(text);
    let bytes = ascii.as_bytes();
    let mut index = 0;
    while index < bytes.len() && is_ascii_space(bytes[index]) {
        index += 1;
    }
    let negative = match bytes.get(index) {
        Some(b'-') => {
            index += 1;
            true
        }
        Some(b'+') => {
            index += 1;
            false
        }
        _ => false,
    };
    let mut digits = String::new();
    let mut previous_digit = false;
    let mut previous_underscore = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_digit() {
            digits.push(byte as char);
            previous_digit = true;
            previous_underscore = false;
        } else if byte == b'_' && previous_digit {
            previous_digit = false;
            previous_underscore = true;
        } else {
            break;
        }
        index += 1;
    }
    if digits.is_empty() || previous_underscore {
        return Err(invalid());
    }
    while index < bytes.len() && is_ascii_space(bytes[index]) {
        index += 1;
    }
    if index != bytes.len() {
        return Err(invalid());
    }
    let magnitude: i128 =
        digits.trim_start_matches('0').parse().unwrap_or(if digits.chars().all(|c| c == '0') { 0 } else { i128::MAX });
    let value = if negative { -magnitude } else { magnitude };
    i64::try_from(value).map_err(|_| PyValueError(format!("int() value out of range: {}", repr(text))))
}

/// `float(text)`: surrounding whitespace, a sign, `_` between digits, non-ASCII decimal digits,
/// `inf`/`infinity`/`nan` in any case; overflow gives infinity, like Python.
pub fn float_from_str(text: &str) -> Result<f64, PyValueError> {
    let invalid = || PyValueError(format!("could not convert string to float: {}", repr(text)));
    let ascii = to_ascii_digits(text);
    let mut cleaned = String::with_capacity(ascii.len());
    if ascii.contains('_') {
        let mut previous = '\0';
        for ch in ascii.chars() {
            if ch == '_' {
                if !previous.is_ascii_digit() {
                    return Err(invalid());
                }
            } else {
                if previous == '_' && !ch.is_ascii_digit() {
                    return Err(invalid());
                }
                cleaned.push(ch);
            }
            previous = ch;
        }
        if previous == '_' {
            return Err(invalid());
        }
    } else {
        cleaned = ascii;
    }
    let trimmed = cleaned.trim_matches(|c: char| c.is_ascii() && is_ascii_space(c as u8));
    let unsigned = trimmed.strip_prefix(['+', '-']).unwrap_or(trimmed);
    let lowered = unsigned.to_ascii_lowercase();
    let special = matches!(lowered.as_str(), "inf" | "infinity" | "nan");
    // Both grammars are `[sign] digits [. digits] [e [sign] digits]` plus the three specials; the
    // character check keeps anything else Rust might grow out of `parse`.
    let syntax_ok = special
        || (!unsigned.is_empty()
            && unsigned.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-')));
    if !syntax_ok {
        return Err(invalid());
    }
    trimmed.parse::<f64>().map_err(|_| invalid())
}

const ALWAYS_SAFE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-~";

/// `urllib.parse.quote(text, safe=safe)`: UTF-8 bytes outside `A-Za-z0-9_.-~` and the ASCII
/// characters of `safe` become `%XX` (upper case). Non-ASCII characters in `safe` are ignored.
pub fn quote(text: &str, safe: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for &byte in text.as_bytes() {
        if ALWAYS_SAFE.contains(&byte) || (byte < 128 && safe.as_bytes().contains(&byte)) {
            out.push(byte as char);
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// `urllib.parse.quote(text)` — `safe='/'`.
pub fn quote_path(text: &str) -> String {
    quote(text, "/")
}

/// `urllib.parse.quote_plus(text, safe=safe)`: like [`quote`], with spaces as `+`.
pub fn quote_plus(text: &str, safe: &str) -> String {
    if !text.contains(' ') {
        return quote(text, safe);
    }
    let mut widened = String::from(safe);
    widened.push(' ');
    quote(text, &widened).replace(' ', "+")
}

/// `urllib.parse.urlencode(pairs)` for string pairs (`quote_plus` with `safe=''`).
pub fn urlencode<K: AsRef<str>, V: AsRef<str>>(pairs: &[(K, V)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", quote_plus(key.as_ref(), ""), quote_plus(value.as_ref(), "")))
        .collect::<Vec<_>>()
        .join("&")
}

/// `urllib.parse.unquote(text)`: `%XX` sequences decoded as UTF-8 with `errors='replace'`; a `%`
/// not followed by two hex digits stays as it is; non-ASCII text passes through untouched.
pub fn unquote(text: &str) -> String {
    if !text.contains('%') {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut pending: Vec<u8> = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    let hex = |b: u8| (b as char).to_digit(16);
    while index < bytes.len() {
        let byte = bytes[index];
        if byte >= 0x80 {
            // A non-ASCII run is copied as is (Python decodes only ASCII runs).
            out.push_str(&String::from_utf8_lossy(&pending));
            pending.clear();
            let ch = text[index..].chars().next().expect("index is on a char boundary");
            out.push(ch);
            index += ch.len_utf8();
            continue;
        }
        if byte == b'%' {
            if let (Some(high), Some(low)) =
                (bytes.get(index + 1).and_then(|b| hex(*b)), bytes.get(index + 2).and_then(|b| hex(*b)))
            {
                pending.push((high * 16 + low) as u8);
                index += 3;
                continue;
            }
        }
        pending.push(byte);
        index += 1;
    }
    out.push_str(&String::from_utf8_lossy(&pending));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_uses_python_whitespace() {
        assert_eq!(split("a\x1cb\u{85}c\u{a0}d\u{200b}e"), ["a", "b", "c", "d\u{200b}e"]);
        assert_eq!(collapse_whitespace("  Этот \t сервер "), "Этот сервер");
    }

    #[test]
    fn slice_counts_code_points() {
        assert_eq!(slice("🙂a🙂b", Some(1), Some(-1)), "a🙂");
        assert_eq!(slice("abc", Some(5), None), "");
        assert_eq!(len("🙂é"), 2);
    }

    #[test]
    fn numbers_parse_like_python() {
        assert_eq!(int_from_str(" 1_000 "), Ok(1000));
        assert_eq!(int_from_str("\u{661}\u{665}"), Ok(15));
        assert!(int_from_str("1.0").is_err());
        assert_eq!(float_from_str("1e-05"), Ok(1e-05));
        assert!(float_from_str("0x10").is_err());
    }

    #[test]
    fn quoting_matches_urllib() {
        assert_eq!(quote("a b/é", ""), "a%20b%2F%C3%A9");
        assert_eq!(quote_path("a b/c"), "a%20b/c");
        assert_eq!(quote_plus("a b+c", ""), "a+b%2Bc");
        assert_eq!(unquote("%E2%82%AC%zz%4"), "€%zz%4");
    }
}
