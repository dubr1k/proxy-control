//! Python semantics the adapters lean on: what a manager's answer looks like to `dict`/`list`
//! code, truthiness, `str()`, `bytes.decode()`.

use panel_model::protocols::AdapterError;
use serde_json::{Map, Value};

use crate::error::crash;

/// The answer as a dict; anything else is what Python crashed on (`AttributeError`, a 500).
pub(crate) fn as_object(value: &Value) -> Result<&Map<String, Value>, AdapterError> {
    value.as_object().ok_or_else(|| crash("the manager answered something that is not an object"))
}

/// The dicts of `for row in rows` with the `isinstance(row, dict)` filter: a list keeps its
/// objects; a dict or a string iterates keys or characters, none of them a dict; anything else is
/// not iterable (Python's `TypeError`).
pub(crate) fn rows(value: &Value) -> Result<Vec<&Map<String, Value>>, AdapterError> {
    match value {
        Value::Array(items) => Ok(items.iter().filter_map(Value::as_object).collect()),
        Value::Object(_) | Value::String(_) => Ok(Vec::new()),
        _ => Err(crash("the manager answered a list that is not a list")),
    }
}

/// `bool(value)`.
pub(crate) fn truthy(value: Option<&Value>) -> bool {
    value.is_some_and(panel_managers::pyvalue::truthy)
}

/// `str(value)` of a JSON value (`str(None)` is `"None"`).
pub(crate) fn py_str(value: Option<&Value>) -> String {
    panel_model::pyrepr::str(value.unwrap_or(&Value::Null))
}

/// `value.get(key) or default` for a text value.
pub(crate) fn text_or<'a>(value: Option<&'a Value>, default: &'a str) -> String {
    if truthy(value) {
        py_str(value)
    } else {
        default.to_string()
    }
}

fn base64_digit(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// `binascii.a2b_base64(data)` without strict mode, i.e. `base64.b64decode(data)`: characters
/// outside the alphabet are skipped, enough padding ends the input, trailing bits are dropped.
/// The error is the `binascii.Error` text.
pub(crate) fn b64decode_lenient(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(data.len() * 3 / 4);
    let (mut quad, mut left, mut pads) = (0u8, 0u8, 0u8);
    let mut count = 0usize;
    for &byte in data {
        if byte == b'=' {
            if quad >= 2 {
                pads += 1;
                if quad + pads >= 4 {
                    return Ok(out);
                }
            }
            continue;
        }
        let Some(digit) = base64_digit(byte) else { continue };
        count += 1;
        pads = 0;
        match quad {
            0 => {
                quad = 1;
                left = digit;
            }
            1 => {
                quad = 2;
                out.push((left << 2) | (digit >> 4));
                left = digit & 0x0f;
            }
            2 => {
                quad = 3;
                out.push((left << 4) | (digit >> 2));
                left = digit & 0x03;
            }
            _ => {
                quad = 0;
                out.push((left << 6) | digit);
            }
        }
    }
    match quad {
        0 => Ok(out),
        1 => Err(format!(
            "Invalid base64-encoded string: number of data characters ({count}) cannot be 1 more than a multiple of 4"
        )),
        _ => Err("Incorrect padding".into()),
    }
}

/// `base64.b64decode(text, validate=True)` (CPython 3.13's strict check, trailing bits allowed).
pub(crate) fn b64decode_strict(text: &str) -> Option<Vec<u8>> {
    if !panel_model::clients::is_strict_base64(text) {
        return None;
    }
    b64decode_lenient(text.as_bytes()).ok()
}

/// `plaintext.decode()` (UTF-8, strict); Python raised `UnicodeDecodeError` (a 500).
pub(crate) fn decode_utf8(bytes: &[u8]) -> Result<String, AdapterError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| crash("the credential is not UTF-8"))
}
