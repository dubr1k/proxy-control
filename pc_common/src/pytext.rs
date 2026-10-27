//! Python text primitives shared by the host and managers.
//!
//! String-repr escaping is shared, but callers retain their existing printability policies:
//! the host and MCP approximate Unicode differently, while the panel uses generated tables.

use std::fmt::Write as _;

/// Python's whitespace set, including the ASCII information separators `\x1c`–`\x1f`.
pub fn is_space(c: char) -> bool {
    matches!(c as u32, 0x09..=0x0d | 0x1c..=0x20 | 0x85 | 0xa0 | 0x1680 | 0x2000..=0x200a | 0x2028 | 0x2029 | 0x202f | 0x205f | 0x3000)
}

/// `str.strip()` without arguments.
pub fn strip(text: &str) -> &str {
    text.trim_matches(is_space)
}

/// `str.split()` without arguments: runs of whitespace separate, with no empty fields.
pub fn split(text: &str) -> Vec<&str> {
    text.split(is_space).filter(|part| !part.is_empty()).collect()
}

/// `str.splitlines()`, without retaining line endings or a final empty line.
pub fn splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((index, c)) = chars.next() {
        if !matches!(
            c,
            '\n' | '\r' | '\u{0b}' | '\u{0c}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}' | '\u{2028}' | '\u{2029}'
        ) {
            continue;
        }
        lines.push(&text[start..index]);
        let mut end = index + c.len_utf8();
        if c == '\r' {
            if let Some(&(next, '\n')) = chars.peek() {
                chars.next();
                end = next + 1;
            }
        }
        start = end;
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// A nonempty run of ASCII digits, not Python's wider Unicode `str.isdigit()` set.
pub fn is_ascii_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

/// The sign and ASCII decimal body accepted by the ASCII-only `int()` consumers.
/// Underscores are retained; range and zero normalization belong to the consumer.
pub fn ascii_int_parts(text: &str) -> Option<(bool, &str)> {
    let text = strip(text);
    let (negative, body) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    if body.is_empty()
        || body.starts_with('_')
        || body.ends_with('_')
        || body.contains("__")
        || !body.bytes().all(|b| b.is_ascii_digit() || b == b'_')
    {
        return None;
    }
    Some((negative, body))
}

/// The first `limit` characters (`text[:limit]`).
pub fn head_chars(text: &str, limit: usize) -> &str {
    match text.char_indices().nth(limit) {
        Some((index, _)) => &text[..index],
        None => text,
    }
}

/// The last `limit` characters, empty for zero.
pub fn tail_chars(text: &str, limit: usize) -> &str {
    if limit == 0 {
        return "";
    }
    match text.char_indices().rev().nth(limit - 1) {
        Some((index, _)) => &text[index..],
        None => text,
    }
}

/// Python's string quoting and escapes using the consumer's Unicode printability policy.
/// C0 controls and DEL are always escaped, even if the predicate accepts them.
pub fn repr_with_printable(text: &str, printable: impl Fn(char) -> bool) -> String {
    let quote = if text.contains('\'') && !text.contains('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f || !printable(c) => {
                let code = c as u32;
                if code <= 0xff {
                    let _ = write!(out, "\\x{code:02x}");
                } else if code <= 0xffff {
                    let _ = write!(out, "\\u{code:04x}");
                } else {
                    let _ = write!(out, "\\U{code:08x}");
                }
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}
