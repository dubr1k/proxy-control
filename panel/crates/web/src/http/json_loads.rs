//! Python's `json.loads(bytes)` as Starlette's `Request.json()` calls it: the same encoding
//! detection (BOMs, UTF-16/32 by null bytes), the C scanner's grammar, and — what FastAPI's 422
//! `json_invalid` body carries — the same error message and character position for every malformed
//! input (golden corpus `tests/fixtures/json_corpus.json`).
//!
//! Values Python accepts but a `serde_json::Value` cannot hold are refused with
//! [`LoadsError::Unrepresentable`] (see DIFFERENCES.md): `NaN`/`Infinity`/`-Infinity`, numbers that
//! overflow a float, lone surrogates. Integers beyond `u64` become floats.

use serde_json::{Map, Number, Value};

/// Why a body is not JSON.
#[derive(Debug, Clone, PartialEq)]
pub enum LoadsError {
    /// `json.JSONDecodeError(msg, doc, pos)`: FastAPI's 422 `json_invalid` at `["body", pos]`.
    Decode { msg: String, pos: usize },
    /// Any other failure of `json.loads` (undecodable bytes, nesting too deep): FastAPI's 400
    /// "There was an error parsing the body".
    Other(&'static str),
    /// Valid for Python, not representable here.
    Unrepresentable { msg: &'static str, pos: usize },
}

/// Bound nesting before constructing a `Value`: validation errors clone missing-field inputs,
/// and response serialization and value destruction recurse. Python's 9997-level scanner limit
/// is unsafe for the panel's HTTP worker stack (a 59,983-byte login body crashed the process).
/// 128 levels are sufficient for typed API documents and stay safe through those later stages.
pub const MAX_DEPTH: usize = 128;

/// `json.loads(bytes)`.
pub fn loads(bytes: &[u8]) -> Result<Value, LoadsError> {
    let text = decode(bytes)?;
    let mut parser = Parser { s: &text, deferred: std::cell::Cell::new(None) };
    let start = parser.skip_ws(0);
    let (value, end) = parser.scan_once(start)?;
    let end = parser.skip_ws(end);
    if end != text.len() {
        return Err(decode_error("Extra data", end));
    }
    if let Some((msg, pos)) = parser.deferred.get() {
        return Err(LoadsError::Unrepresentable { msg, pos });
    }
    Ok(value)
}

fn decode_error(msg: &str, pos: usize) -> LoadsError {
    LoadsError::Decode { msg: msg.to_string(), pos }
}

/// `bytes.decode(json.detect_encoding(b), 'surrogatepass')` into code points (a lone surrogate is
/// kept as its code point so positions stay Python's).
fn decode(b: &[u8]) -> Result<Vec<u32>, LoadsError> {
    let undecodable = LoadsError::Other("undecodable body");
    let starts = |prefix: &[u8]| b.starts_with(prefix);
    if starts(&[0, 0, 0xfe, 0xff]) {
        return utf32(&b[4..], true);
    }
    if starts(&[0xff, 0xfe, 0, 0]) {
        return utf32(&b[4..], false);
    }
    if starts(&[0xfe, 0xff]) {
        return utf16(&b[2..], true);
    }
    if starts(&[0xff, 0xfe]) {
        return utf16(&b[2..], false);
    }
    if starts(&[0xef, 0xbb, 0xbf]) {
        return utf8_surrogatepass(&b[3..]).ok_or(undecodable);
    }
    if b.len() >= 4 {
        if b[0] == 0 {
            return if b[1] != 0 { utf16(b, true) } else { utf32(b, true) };
        }
        if b[1] == 0 {
            return if b[2] != 0 || b[3] != 0 { utf16(b, false) } else { utf32(b, false) };
        }
    } else if b.len() == 2 {
        if b[0] == 0 {
            return utf16(b, true);
        }
        if b[1] == 0 {
            return utf16(b, false);
        }
    }
    utf8_surrogatepass(b).ok_or(undecodable)
}

fn utf16(b: &[u8], big: bool) -> Result<Vec<u32>, LoadsError> {
    if b.len() % 2 != 0 {
        return Err(LoadsError::Other("truncated UTF-16"));
    }
    let units = b.chunks(2).map(|pair| {
        if big {
            u16::from_be_bytes([pair[0], pair[1]])
        } else {
            u16::from_le_bytes([pair[0], pair[1]])
        }
    });
    // Python's UTF-16 decoder rejects lone surrogates even with surrogatepass.
    char::decode_utf16(units).map(|unit| unit.map(u32::from).map_err(|_| LoadsError::Other("invalid UTF-16"))).collect()
}

fn utf32(b: &[u8], big: bool) -> Result<Vec<u32>, LoadsError> {
    if b.len() % 4 != 0 {
        return Err(LoadsError::Other("truncated UTF-32"));
    }
    b.chunks(4)
        .map(|quad| {
            let value = if big {
                u32::from_be_bytes([quad[0], quad[1], quad[2], quad[3]])
            } else {
                u32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]])
            };
            if value > 0x10ffff {
                Err(LoadsError::Other("invalid UTF-32"))
            } else {
                Ok(value)
            }
        })
        .collect()
}

/// UTF-8 with `surrogatepass`: encoded surrogates (`ED A0..BF xx`) decode to their code point.
fn utf8_surrogatepass(b: &[u8]) -> Option<Vec<u32>> {
    let mut out = Vec::with_capacity(b.len());
    let mut index = 0;
    while index < b.len() {
        let rest = &b[index..];
        let first = rest[0];
        let width = match first {
            0x00..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => return None,
        };
        if rest.len() < width {
            return None;
        }
        if first == 0xed && rest[1] >= 0xa0 && rest[1] <= 0xbf && rest[2] & 0xc0 == 0x80 {
            out.push(0xd000 | (u32::from(rest[1] & 0x3f) << 6) | u32::from(rest[2] & 0x3f));
            index += 3;
            continue;
        }
        let ch = std::str::from_utf8(&rest[..width]).ok()?.chars().next()?;
        out.push(ch as u32);
        index += width;
    }
    Some(out)
}

struct Parser<'a> {
    s: &'a [u32],
    /// The first value Python accepts but a `Value` cannot hold (refused only once the whole
    /// document parsed, so Python's own decode errors keep precedence).
    deferred: std::cell::Cell<Option<(&'static str, usize)>>,
}

const fn is_ws(c: u32) -> bool {
    matches!(c, 0x20 | 0x09 | 0x0a | 0x0d)
}

fn is_digit(c: u32) -> bool {
    (0x30..=0x39).contains(&c)
}

impl Parser<'_> {
    /// Records a value Python accepts but a `Value` cannot hold; it reads as `null` until the
    /// parse ends.
    fn defer(&self, msg: &'static str, pos: usize, end: usize) -> (Value, usize) {
        if self.deferred.get().is_none() {
            self.deferred.set(Some((msg, pos)));
        }
        (Value::Null, end)
    }

    fn at(&self, index: usize) -> Option<u32> {
        self.s.get(index).copied()
    }

    fn skip_ws(&self, mut index: usize) -> usize {
        while self.at(index).is_some_and(is_ws) {
            index += 1;
        }
        index
    }

    fn literal(&self, index: usize, word: &str) -> bool {
        let len = word.len();
        index + len <= self.s.len()
            && word.bytes().enumerate().all(|(offset, byte)| self.s[index + offset] == u32::from(byte))
    }

    /// `scan_once(s, idx)`; a missing value is "Expecting value" at `idx` (the StopIteration).
    /// `scan_once(s, idx)` without recursion: containers are kept on an explicit stack (Python's C
    /// scanner recurses up to its C recursion limit, [`MAX_DEPTH`]). Errors carry the C scanner's
    /// messages and positions; a missing value is "Expecting value" at its index (StopIteration).
    fn scan_once(&mut self, start: usize) -> Result<(Value, usize), LoadsError> {
        let mut stack: Vec<Frame> = Vec::new();
        let mut index = start;
        loop {
            // Read one value at `index`: a scalar, an empty container, or the opening of one.
            let (mut value, mut end) = match self.at(index) {
                Some(0x7b) | Some(0x5b) if stack.len() >= MAX_DEPTH => {
                    return Err(LoadsError::Other("maximum recursion depth exceeded"));
                }
                Some(0x7b) => {
                    let inner = self.skip_ws(index + 1);
                    if self.at(inner) == Some(0x7d) {
                        (Value::Object(Map::new()), inner + 1)
                    } else {
                        let (key, next) = self.object_key(inner)?;
                        stack.push(Frame::Object(Map::new(), key));
                        index = next;
                        continue;
                    }
                }
                Some(0x5b) => {
                    let inner = self.skip_ws(index + 1);
                    if self.at(inner) == Some(0x5d) {
                        (Value::Array(Vec::new()), inner + 1)
                    } else {
                        stack.push(Frame::Array(Vec::new()));
                        index = inner;
                        continue;
                    }
                }
                _ => self.scalar(index)?,
            };
            // Fold the finished value into the open containers.
            loop {
                let Some(frame) = stack.last_mut() else {
                    return Ok((value, end));
                };
                let close = match frame {
                    Frame::Array(items) => {
                        items.push(value);
                        0x5d
                    }
                    Frame::Object(map, key) => {
                        map.insert(std::mem::take(key), value);
                        0x7d
                    }
                };
                let after = self.skip_ws(end);
                if self.at(after) == Some(close) {
                    value = match stack.pop().expect("an open container") {
                        Frame::Array(items) => Value::Array(items),
                        Frame::Object(map, _) => Value::Object(map),
                    };
                    end = after + 1;
                    continue;
                }
                if self.at(after) != Some(0x2c) {
                    return Err(decode_error("Expecting ',' delimiter", after));
                }
                // Python 3.13 has no "Illegal trailing comma" message (3.14 does): after a comma the
                // next key or value is simply expected.
                let next = self.skip_ws(after + 1);
                index = next;
                if let Some(Frame::Object(_, key)) = stack.last_mut() {
                    let (name, value_start) = self.object_key(next)?;
                    *key = name;
                    index = value_start;
                }
                break;
            }
        }
    }

    /// A key, its `:` and the whitespace after it: where the value starts.
    fn object_key(&self, index: usize) -> Result<(String, usize), LoadsError> {
        if self.at(index) != Some(0x22) {
            return Err(decode_error("Expecting property name enclosed in double quotes", index));
        }
        let (key, next) = self.scanstring(index + 1)?;
        let colon = self.skip_ws(next);
        if self.at(colon) != Some(0x3a) {
            return Err(decode_error("Expecting ':' delimiter", colon));
        }
        Ok((key, self.skip_ws(colon + 1)))
    }

    /// Strings, literals and numbers.
    fn scalar(&self, index: usize) -> Result<(Value, usize), LoadsError> {
        let Some(c) = self.at(index) else {
            return Err(decode_error("Expecting value", index));
        };
        match c {
            0x22 => {
                let (text, end) = self.scanstring(index + 1)?;
                Ok((Value::String(text), end))
            }
            0x6e if self.literal(index, "null") => Ok((Value::Null, index + 4)),
            0x74 if self.literal(index, "true") => Ok((Value::Bool(true), index + 4)),
            0x66 if self.literal(index, "false") => Ok((Value::Bool(false), index + 5)),
            0x4e if self.literal(index, "NaN") => Ok(self.defer("NaN is not accepted", index, index + 3)),
            0x49 if self.literal(index, "Infinity") => Ok(self.defer("Infinity is not accepted", index, index + 8)),
            0x2d if self.literal(index + 1, "Infinity") => Ok(self.defer("Infinity is not accepted", index, index + 9)),
            _ => self.number(index),
        }
    }

    fn number(&self, start: usize) -> Result<(Value, usize), LoadsError> {
        let len = self.s.len();
        let mut index = start;
        if self.at(index) == Some(0x2d) {
            index += 1;
            if index >= len {
                return Err(decode_error("Expecting value", start));
            }
        }
        match self.at(index) {
            Some(c) if (0x31..=0x39).contains(&c) => {
                index += 1;
                while self.at(index).is_some_and(is_digit) {
                    index += 1;
                }
            }
            Some(0x30) => index += 1,
            _ => return Err(decode_error("Expecting value", start)),
        }
        let mut is_float = false;
        if index + 1 < len && self.s[index] == 0x2e && is_digit(self.s[index + 1]) {
            is_float = true;
            index += 2;
            while self.at(index).is_some_and(is_digit) {
                index += 1;
            }
        }
        if index + 1 < len && (self.s[index] == 0x65 || self.s[index] == 0x45) {
            let e_start = index;
            index += 1;
            if index + 1 < len && (self.s[index] == 0x2d || self.s[index] == 0x2b) {
                index += 1;
            }
            let digits_start = index;
            while self.at(index).is_some_and(is_digit) {
                index += 1;
            }
            if index > digits_start {
                is_float = true;
            } else {
                index = e_start;
            }
        }
        let text: String = self.s[start..index].iter().map(|c| char::from_u32(*c).unwrap_or('0')).collect();
        let number = if is_float {
            let value: f64 = text.parse().map_err(|_| decode_error("Expecting value", start))?;
            match Number::from_f64(value) {
                Some(number) => number,
                None => return Ok(self.defer("number out of range", start, index)),
            }
        } else if let Ok(value) = text.parse::<i64>() {
            Number::from(value)
        } else if let Ok(value) = text.parse::<u64>() {
            Number::from(value)
        } else {
            let value: f64 = text.parse().map_err(|_| decode_error("Expecting value", start))?;
            match Number::from_f64(value) {
                Some(number) => number,
                None => return Ok(self.defer("number out of range", start, index)),
            }
        };
        Ok((Value::Number(number), index))
    }

    /// `scanstring(s, end)` with `strict=True`; `end` is just past the opening quote.
    fn scanstring(&self, mut end: usize) -> Result<(String, usize), LoadsError> {
        let begin = end - 1;
        let len = self.s.len();
        let mut chunks: Vec<u32> = Vec::new();
        loop {
            let mut next = end;
            let mut c = 0;
            while next < len {
                c = self.s[next];
                if c == 0x22 || c == 0x5c {
                    break;
                }
                if c <= 0x1f {
                    return Err(decode_error("Invalid control character at", next));
                }
                next += 1;
            }
            if next >= len || !(c == 0x22 || c == 0x5c) {
                return Err(decode_error("Unterminated string starting at", begin));
            }
            chunks.extend_from_slice(&self.s[end..next]);
            next += 1;
            if c == 0x22 {
                end = next;
                break;
            }
            if next == len {
                return Err(decode_error("Unterminated string starting at", begin));
            }
            let escape = self.s[next];
            if escape != 0x75 {
                end = next + 1;
                let decoded = match escape {
                    0x22 => 0x22,
                    0x5c => 0x5c,
                    0x2f => 0x2f,
                    0x62 => 0x08,
                    0x66 => 0x0c,
                    0x6e => 0x0a,
                    0x72 => 0x0d,
                    0x74 => 0x09,
                    _ => return Err(decode_error("Invalid \\escape", end - 2)),
                };
                chunks.push(decoded);
                continue;
            }
            next += 1;
            end = next + 4;
            if end >= len {
                return Err(decode_error("Invalid \\uXXXX escape", next - 1));
            }
            let mut code = 0u32;
            while next < end {
                let digit = char::from_u32(self.s[next]).and_then(|ch| ch.to_digit(16));
                match digit {
                    Some(digit) if self.s[next] < 0x80 => code = (code << 4) | digit,
                    _ => return Err(decode_error("Invalid \\uXXXX escape", end - 5)),
                }
                next += 1;
            }
            if (0xd800..=0xdbff).contains(&code) && end + 6 < len && self.s[next] == 0x5c && self.s[next + 1] == 0x75 {
                next += 2;
                let mut low = 0u32;
                let pair_end = end + 6;
                while next < pair_end {
                    let digit = char::from_u32(self.s[next]).and_then(|ch| ch.to_digit(16));
                    match digit {
                        Some(digit) if self.s[next] < 0x80 => low = (low << 4) | digit,
                        _ => return Err(decode_error("Invalid \\uXXXX escape", pair_end - 5)),
                    }
                    next += 1;
                }
                if (0xdc00..=0xdfff).contains(&low) {
                    code = 0x10000 + (((code - 0xd800) << 10) | (low - 0xdc00));
                    end = pair_end;
                }
            }
            chunks.push(code);
        }
        let mut text = String::with_capacity(chunks.len());
        for code in chunks {
            match char::from_u32(code) {
                Some(ch) => text.push(ch),
                None => {
                    self.defer("lone surrogates are not accepted", begin, end);
                    text.push('\u{fffd}');
                }
            }
        }
        Ok((text, end))
    }
}

/// An open container of the scanner.
enum Frame {
    Array(Vec<Value>),
    /// The object so far and the key whose value is being read.
    Object(Map<String, Value>, String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_keys_keep_the_first_position_and_the_last_value() {
        let value = loads(br#"{"a": 1, "b": 2, "a": 3}"#).unwrap();
        assert_eq!(serde_json::to_string(&value).unwrap(), r#"{"a":3,"b":2}"#);
    }

    #[test]
    fn positions_count_code_points() {
        assert_eq!(
            loads("{\"é\": 1, x}".as_bytes()),
            Err(LoadsError::Decode { msg: "Expecting property name enclosed in double quotes".into(), pos: 9 })
        );
    }

    #[test]
    fn deep_nesting_is_not_a_decode_error() {
        let deep = "[".repeat(MAX_DEPTH + 1) + &"]".repeat(MAX_DEPTH + 1);
        assert!(matches!(loads(deep.as_bytes()), Err(LoadsError::Other(_))));
        let deepest = "[".repeat(MAX_DEPTH) + &"]".repeat(MAX_DEPTH);
        assert!(loads(deepest.as_bytes()).is_ok());
        let objects = "{\"a\":".repeat(MAX_DEPTH + 1) + "1" + &"}".repeat(MAX_DEPTH + 1);
        assert!(matches!(loads(objects.as_bytes()), Err(LoadsError::Other(_))));
    }
}
