//! The client-list cursor: `base64.urlsafe_b64encode(json.dumps([rank, created_at, id]))` with the
//! padding stripped, read back exactly as Python reads it (non-strict base64, `json.loads` of
//! bytes with its encoding detection).

use base64::engine::general_purpose::URL_SAFE;
use base64::Engine as _;
use serde_json::{json, Value};

/// `[rank, created_at, id]` → the cursor text.
pub fn encode(rank: i64, created_at: i64, id: &str) -> String {
    let text = panel_core::pyjson::dumps_default(&json!([rank, created_at, id]));
    URL_SAFE.encode(text.as_bytes()).trim_end_matches('=').to_string()
}

/// The position a cursor names, or `None` for every input Python refuses with
/// "invalid client cursor".
pub fn decode(cursor: &str) -> Option<(i64, i64, String)> {
    if !cursor.is_ascii() {
        // `_bytes_from_decode_data`: a str must be ASCII.
        return None;
    }
    let padding = (4 - cursor.len() % 4) % 4;
    let padded = format!("{cursor}{}", "=".repeat(padding));
    let bytes = a2b_base64(&padded.replace('-', "+").replace('_', "/"))?;
    let value = json_loads(&bytes)?;
    let items = value.as_array().filter(|items| items.len() == 3)?;
    let rank = items[0].as_i64().filter(|_| !items[0].is_f64()).filter(|rank| (0..=2).contains(rank))?;
    let created_at = items[1].as_i64().filter(|_| !items[1].is_f64()).filter(|value| *value >= 0)?;
    let id = items[2].as_str()?.to_string();
    Some((rank, created_at, id))
}

fn sextet(byte: u8) -> Option<u32> {
    Some(match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    } as u32)
}

/// CPython's `binascii.a2b_base64(data, strict_mode=False)`: characters outside the alphabet are
/// skipped, a complete pad sequence ends the input, a leftover partial quad is an error.
fn a2b_base64(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut quad, mut pads, mut accumulator) = (0u32, 0u32, 0u32);
    for &byte in text.as_bytes() {
        if byte == b'=' {
            pads += 1;
            if quad >= 2 && quad + pads >= 4 {
                return Some(out);
            }
            continue;
        }
        let Some(value) = sextet(byte) else {
            continue;
        };
        pads = 0;
        match quad {
            0 => {
                accumulator = value;
                quad = 1;
            }
            1 => {
                out.push(((accumulator << 2) | (value >> 4)) as u8);
                accumulator = value & 0x0f;
                quad = 2;
            }
            2 => {
                out.push(((accumulator << 4) | (value >> 2)) as u8);
                accumulator = value & 0x03;
                quad = 3;
            }
            _ => {
                out.push(((accumulator << 6) | value) as u8);
                quad = 0;
            }
        }
    }
    (quad == 0).then_some(out)
}

/// `json.loads(bytes)`: the encoding detected as `json.detect_encoding` does, then parsed.
fn json_loads(bytes: &[u8]) -> Option<Value> {
    let text = decode_detected(bytes)?;
    serde_json::from_str(&text).ok()
}

fn decode_detected(b: &[u8]) -> Option<String> {
    let utf16 =
        |data: &[u8], big: bool| -> Option<String> {
            if data.len() % 2 != 0 {
                return None;
            }
            let units: Vec<u16> =
                data.chunks(2)
                    .map(|pair| {
                        if big {
                            u16::from_be_bytes([pair[0], pair[1]])
                        } else {
                            u16::from_le_bytes([pair[0], pair[1]])
                        }
                    })
                    .collect();
            String::from_utf16(&units).ok()
        };
    let utf32 = |data: &[u8], big: bool| -> Option<String> {
        if data.len() % 4 != 0 {
            return None;
        }
        data.chunks(4)
            .map(|quad| {
                let code = if big {
                    u32::from_be_bytes([quad[0], quad[1], quad[2], quad[3]])
                } else {
                    u32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]])
                };
                char::from_u32(code)
            })
            .collect()
    };
    if let Some(rest) = b.strip_prefix(&[0x00, 0x00, 0xfe, 0xff]) {
        return utf32(rest, true);
    }
    if let Some(rest) = b.strip_prefix(&[0xff, 0xfe, 0x00, 0x00]) {
        return utf32(rest, false);
    }
    if let Some(rest) = b.strip_prefix(&[0xfe, 0xff]) {
        return utf16(rest, true);
    }
    if let Some(rest) = b.strip_prefix(&[0xff, 0xfe]) {
        return utf16(rest, false);
    }
    if let Some(rest) = b.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        return String::from_utf8(rest.to_vec()).ok();
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
    String::from_utf8(b.to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursors_round_trip_and_match_python_bytes() {
        let cursor = encode(0, 1_793_005_856, "373e72ef-341d-4ff2-9da7-6d86115cd8b9");
        assert_eq!(cursor, "WzAsIDE3OTMwMDU4NTYsICIzNzNlNzJlZi0zNDFkLTRmZjItOWRhNy02ZDg2MTE1Y2Q4YjkiXQ");
        assert_eq!(decode(&cursor), Some((0, 1_793_005_856, "373e72ef-341d-4ff2-9da7-6d86115cd8b9".into())));
    }

    #[test]
    fn invalid_cursors_are_refused_like_python() {
        let b64 = |text: &str| URL_SAFE.encode(text).trim_end_matches('=').to_string();
        for bad in [
            "bogus".to_string(),
            "A".to_string(),
            "ж".to_string(),
            b64("[3, 1, \"x\"]"),
            b64("[true, 1, \"x\"]"),
            b64("[0, 1.0, \"x\"]"),
            b64("[0, -1, \"x\"]"),
            b64("[0, 9223372036854775808, \"x\"]"),
            b64("[0, 1, 2]"),
            b64("[0, 1]"),
            b64("{}"),
        ] {
            assert_eq!(decode(&bad), None, "{bad}");
        }
        // Non-alphabet characters are skipped, padding ends the input (non-strict base64).
        let good = b64("[1, 2, \"x\"]");
        assert_eq!(decode(&format!("{}!!", good)), Some((1, 2, "x".into())));
        // json.loads detects UTF-16 too.
        let utf16: Vec<u8> = "[2, 3, \"y\"]".encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
        let cursor = URL_SAFE.encode(utf16).trim_end_matches('=').to_string();
        assert_eq!(decode(&cursor), Some((2, 3, "y".into())));
    }
}
