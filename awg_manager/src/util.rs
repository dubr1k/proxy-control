//! Small Python-compatible helpers (candidates for `pc_common`): `int()` parsing, `repr()` of a
//! string, `datetime.isoformat()` in UTC.

use std::time::{SystemTime, UNIX_EPOCH};

/// An integer as Python's `int(text, base)` reads it: surrounding whitespace, an optional sign,
/// `_` between digits, and a `0o` prefix in base 8.
pub fn parse_int(text: &str, base: u32) -> Option<i64> {
    let text = text.trim();
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let digits = if base == 8 {
        digits.strip_prefix("0o").or_else(|| digits.strip_prefix("0O")).unwrap_or(digits)
    } else {
        digits
    };
    if digits.is_empty() || digits.starts_with('_') || digits.ends_with('_') || digits.contains("__") {
        return None;
    }
    let cleaned = digits.replace('_', "");
    if !cleaned.bytes().all(|b| (b as char).is_digit(base)) {
        return None;
    }
    let value = i64::from_str_radix(&cleaned, base).ok()?;
    Some(if negative { -value } else { value })
}

/// `repr(text)` for the messages that quote a configuration value.
pub fn py_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

fn utc_parts(now: SystemTime) -> (String, u32) {
    let since = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since.as_secs() as i64;
    let (year, month, day) = pc_common::logger::civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    let text = format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}", rem / 3600, rem % 3600 / 60, rem % 60);
    (text, since.subsec_millis())
}

/// `datetime.now(timezone.utc).isoformat(timespec="seconds")`: `2026-10-20T08:50:28+00:00`.
pub fn iso_seconds(now: SystemTime) -> String {
    format!("{}+00:00", utc_parts(now).0)
}

/// `…isoformat(timespec="milliseconds").replace("+00:00", "Z")`: `2026-10-20T08:49:45.713Z`.
pub fn iso_millis_z(now: SystemTime) -> String {
    let (text, millis) = utc_parts(now);
    format!("{text}.{millis:03}Z")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn integers_follow_python_int() {
        assert_eq!(parse_int("660", 8), Some(0o660));
        assert_eq!(parse_int("0o640", 8), Some(0o640));
        assert_eq!(parse_int(" 1_000 ", 10), Some(1000));
        assert_eq!(parse_int("+7", 10), Some(7));
        assert_eq!(parse_int("-5", 10), Some(-5));
        for bad in ["", "9x", "1__0", "_1", "1_", "+", "0x10"] {
            assert_eq!(parse_int(bad, 10), None, "{bad}");
        }
        assert_eq!(parse_int("9", 8), None);
    }

    #[test]
    fn repr_quotes_like_python() {
        assert_eq!(py_repr("garbage"), "'garbage'");
        assert_eq!(py_repr("it's"), "\"it's\"");
        assert_eq!(py_repr("a\\b\n"), "'a\\\\b\\n'");
    }

    #[test]
    fn timestamps_are_utc_isoformat() {
        let at = UNIX_EPOCH + Duration::from_millis(1_792_488_535_374);
        assert_eq!(iso_seconds(at), "2026-10-20T09:28:55+00:00");
        assert_eq!(iso_millis_z(at), "2026-10-20T09:28:55.374Z");
    }
}
