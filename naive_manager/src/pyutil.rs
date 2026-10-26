//! The few Python built-ins the manager's text handling depends on, with Python's exact
//! semantics: `str.isspace`/`\s`, `str.splitlines`, `str.strip`, `urllib.parse.quote`,
//! `datetime.isoformat`/`fromisoformat`, `secrets.token_urlsafe`, and a re-entrant lock
//! (`threading.RLock`), which the manager's locking discipline relies on.

use std::sync::{Condvar, Mutex, PoisonError};
use std::thread::ThreadId;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use sha2::{Digest, Sha256};

/// `str.isspace()` — also what `\s` matches in a Python `str` pattern. Python counts the
/// information separators U+001C–U+001F as whitespace; Rust does not.
pub fn is_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `str.strip()`.
pub fn strip(text: &str) -> &str {
    text.trim_matches(is_space)
}

/// `str.lstrip()`.
pub fn lstrip(text: &str) -> &str {
    text.trim_start_matches(is_space)
}

/// `re.match(r"^(\s*)", line).group(1)`.
pub fn leading_space(line: &str) -> &str {
    &line[..line.len() - lstrip(line).len()]
}

/// `str.split()` with no argument.
pub fn split_whitespace(text: &str) -> Vec<&str> {
    text.split(is_space).filter(|part| !part.is_empty()).collect()
}

fn is_line_break(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{0b}' | '\u{0c}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

/// `str.splitlines()`: every Unicode line boundary, `\r\n` as one, no trailing empty line.
pub fn splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((index, c)) = chars.next() {
        if !is_line_break(c) {
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

/// `bytes.splitlines()`: `\n`, `\r` and `\r\n` only.
pub fn splitlines_bytes(data: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index < data.len() {
        match data[index] {
            b'\n' => {
                lines.push(&data[start..index]);
                index += 1;
                start = index;
            }
            b'\r' => {
                lines.push(&data[start..index]);
                index += if data.get(index + 1) == Some(&b'\n') { 2 } else { 1 };
                start = index;
            }
            _ => index += 1,
        }
    }
    if start < data.len() {
        lines.push(&data[start..]);
    }
    lines
}

/// `"\n".join(lines)`.
pub fn join_lines<S: AsRef<str>>(lines: &[S]) -> String {
    let mut out = String::new();
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        out.push_str(line.as_ref());
    }
    out
}

/// `urllib.parse.quote(text, safe="")`: UTF-8, everything but `A-Za-z0-9_.-~` escaped.
pub fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `secrets.token_urlsafe(n)`.
pub fn token_urlsafe(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    getrandom::fill(&mut bytes).expect("the system random source is available");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// `secrets.compare_digest(a, b)` for two `str`: non-ASCII text is a `TypeError`.
pub fn compare_digest(a: &str, b: &str) -> Result<bool, crate::error::Error> {
    if !a.is_ascii() || !b.is_ascii() {
        return Err(crate::error::Error::Other("comparing strings with non-ASCII characters is not supported".into()));
    }
    Ok(pc_common::constant_time_eq(a.as_bytes(), b.as_bytes()))
}

/// The current UTC time as (seconds, microseconds) since the epoch.
pub fn now_parts() -> (i64, u32) {
    let since = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    (since.as_secs() as i64, since.subsec_micros())
}

fn civil(secs: i64) -> (i64, u32, u32, i64, i64, i64) {
    let (year, month, day) = pc_common::logger::civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    (year, month, day, rem / 3600, rem % 3600 / 60, rem % 60)
}

/// `datetime.fromtimestamp(t, UTC).isoformat()`: microseconds only when not zero.
pub fn isoformat(secs: i64, micros: u32) -> String {
    let (y, mo, d, h, mi, s) = civil(secs);
    let fraction = if micros == 0 { String::new() } else { format!(".{micros:06}") };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}{fraction}+00:00")
}

/// `datetime.now(UTC).isoformat()`.
pub fn now_iso() -> String {
    let (secs, micros) = now_parts();
    isoformat(secs, micros)
}

/// `datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")`: the backup pair's name.
pub fn backup_stamp() -> String {
    let (secs, micros) = now_parts();
    let (y, mo, d, h, mi, s) = civil(secs);
    format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}.{micros:06}Z")
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = month as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        _ => 28,
    }
}

fn digits(text: &[u8], at: usize, count: usize) -> Option<(i64, usize)> {
    let slice = text.get(at..at + count)?;
    if !slice.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some((slice.iter().fold(0i64, |acc, b| acc * 10 + (b - b'0') as i64), at + count))
}

/// `_find_isoformat_datetime_separator` of CPython's `_datetime`.
fn separator_location(s: &[u8]) -> usize {
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    let len = s.len();
    if len == 7 {
        return 7;
    }
    if at(4) == b'-' {
        if at(5) == b'W' {
            if len < 8 {
                return usize::MAX;
            }
            if len > 8 && at(8) == b'-' {
                if len == 9 {
                    return usize::MAX;
                }
                if len > 10 && at(10).is_ascii_digit() {
                    return 8;
                }
                return 10;
            }
            return 8;
        }
        return 10;
    }
    if at(4) == b'W' {
        let mut idx = 7;
        while idx < len && at(idx).is_ascii_digit() {
            idx += 1;
        }
        if idx < 9 {
            return idx;
        }
        return if idx % 2 == 0 { 7 } else { 8 };
    }
    8
}

/// `parse_isoformat_date`: (year, month, day), week dates included.
fn parse_date(s: &[u8]) -> Option<(i64, u32, u32)> {
    let (year, mut p) = digits(s, 0, 4)?;
    let separated = s.get(p) == Some(&b'-');
    if separated {
        p += 1;
    }
    if s.get(p) == Some(&b'W') {
        let (week, after) = digits(s, p + 1, 2)?;
        p = after;
        let weekday = if p < s.len() {
            if separated {
                if s.get(p) != Some(&b'-') {
                    return None;
                }
                p += 1;
            }
            digits(s, p, 1)?.0
        } else {
            1
        };
        if week <= 0 || week >= 53 {
            let first = days_from_civil(year, 1, 1);
            let first_weekday = (first + 3).rem_euclid(7); // Monday = 0
            if !(week == 53 && (first_weekday == 3 || (first_weekday == 2 && is_leap(year)))) {
                return None;
            }
        }
        if !(1..=7).contains(&weekday) {
            return None;
        }
        let first = days_from_civil(year, 1, 1);
        let first_weekday = (first + 3).rem_euclid(7);
        let mut week1_monday = first - first_weekday;
        if first_weekday > 3 {
            week1_monday += 7;
        }
        let days = week1_monday + (week - 1) * 7 + weekday - 1;
        let (y, m, d) = pc_common::logger::civil_from_days(days);
        return Some((y, m, d));
    }
    let (month, after) = digits(s, p, 2)?;
    p = after;
    if separated {
        if s.get(p) != Some(&b'-') {
            return None;
        }
        p += 1;
    }
    let (day, _) = digits(s, p, 2)?;
    Some((year, month as u32, day as u32))
}

/// `parse_hh_mm_ss_ff`: `[HH[:?MM[:?SS[{.,}f+]]]]`; the flag is "something follows".
fn parse_time(s: &[u8], start: usize, end: usize) -> Option<([i64; 4], bool)> {
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    let mut values = [0i64; 4];
    let mut p = start;
    let mut separated = true;
    for (index, slot) in values.iter_mut().take(3).enumerate() {
        let (value, after) = digits(s, p, 2)?;
        *slot = value;
        let c = at(after);
        p = after + 1;
        if index == 0 {
            separated = c == b':';
        }
        if p >= end {
            return Some((values, c != 0));
        } else if separated && c == b':' {
            continue;
        } else if c == b'.' || c == b',' {
            break;
        } else if !separated {
            p -= 1;
        } else {
            return None;
        }
    }
    // The fraction is parsed whatever ended the loop, as the C implementation does.
    let remains = end.saturating_sub(p);
    let take = remains.min(6);
    if take == 0 {
        return None;
    }
    let (micro, mut q) = digits(s, p, take)?;
    values[3] = micro * 10i64.pow((6 - take) as u32);
    while at(q).is_ascii_digit() {
        q += 1;
    }
    Some((values, at(q) != 0))
}

/// `datetime.fromisoformat(text).timestamp()` as CPython 3.13's C implementation reads it;
/// a time without an offset is taken as UTC (the container's local time).
pub fn fromisoformat_timestamp(text: &str) -> Option<f64> {
    let s = text.as_bytes();
    let separator = separator_location(s);
    let (year, month, day) = parse_date(s.get(..separator.min(s.len()))?)?;
    let (mut clock, mut offset) = ([0i64; 4], 0i64);
    if separator != usize::MAX && s.len() > separator {
        let start = separator + 1;
        let end = s.len();
        let mut tz = start;
        while tz < end && !matches!(s[tz], b'Z' | b'+' | b'-') {
            tz += 1;
        }
        let (parsed, trailing) = parse_time(s, start, tz)?;
        clock = parsed;
        if tz == end {
            if trailing {
                return None;
            }
        } else if s[tz] == b'Z' {
            if tz + 1 != end {
                return None;
            }
        } else {
            let sign = if s[tz] == b'-' { -1 } else { 1 };
            let (zone, rest) = parse_time(s, tz + 1, end)?;
            if !(0..24).contains(&zone[0]) || !(0..60).contains(&zone[1]) || !(0..60).contains(&zone[2]) || rest {
                return None;
            }
            offset = sign * (zone[0] * 3600 + zone[1] * 60 + zone[2]);
            clock[3] -= sign * zone[3];
        }
    } else if separator == usize::MAX {
        return None;
    }
    if !(1..=9999).contains(&year) || !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    if !(0..24).contains(&clock[0]) || !(0..60).contains(&clock[1]) || !(0..60).contains(&clock[2]) {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let seconds = days * 86_400 + clock[0] * 3600 + clock[1] * 60 + clock[2] - offset;
    Some(seconds as f64 + clock[3] as f64 / 1_000_000.0)
}

/// `pathlib.Path(name).name == name`: a bare file name.
pub fn is_bare_name(name: &str) -> bool {
    !name.contains('/') && name != "."
}

/// `threading.RLock`: the owning thread may lock it again; others wait.
#[derive(Default)]
pub struct ReentrantMutex {
    owner: Mutex<Option<(ThreadId, usize)>>,
    released: Condvar,
}

#[must_use]
pub struct ReentrantGuard<'a> {
    lock: &'a ReentrantMutex,
    // Tied to the thread that took it.
    _not_send: std::marker::PhantomData<*const ()>,
}

impl ReentrantMutex {
    pub fn lock(&self) -> ReentrantGuard<'_> {
        let me = std::thread::current().id();
        let mut owner = self.owner.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            match owner.as_mut() {
                None => {
                    *owner = Some((me, 1));
                    break;
                }
                Some((id, count)) if *id == me => {
                    *count += 1;
                    break;
                }
                Some(_) => owner = self.released.wait(owner).unwrap_or_else(PoisonError::into_inner),
            }
        }
        ReentrantGuard { lock: self, _not_send: std::marker::PhantomData }
    }
}

impl Drop for ReentrantGuard<'_> {
    fn drop(&mut self) {
        let mut owner = self.lock.owner.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((_, count)) = owner.as_mut() {
            *count -= 1;
            if *count == 0 {
                *owner = None;
                self.lock.released.notify_all();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitlines_and_whitespace_follow_python() {
        assert_eq!(splitlines("a\nb\r\nc\rd\u{2028}e\u{0c}f\n"), ["a", "b", "c", "d", "e", "f"]);
        assert_eq!(splitlines(""), Vec::<&str>::new());
        assert_eq!(splitlines("\n"), [""]);
        assert_eq!(splitlines("a\n\nb"), ["a", "", "b"]);
        assert_eq!(splitlines_bytes(b"a\nb\r\nc\rd\x0be"), [&b"a"[..], b"b", b"c", b"d\x0be"]);
        assert_eq!(strip("\u{1f} a \u{3000}"), "a");
        assert_eq!(leading_space("  \tx y"), "  \t");
        assert_eq!(split_whitespace(" a  b\u{a0}c "), ["a", "b", "c"]);
    }

    #[test]
    fn quote_matches_urllib() {
        // urllib.parse.quote(value, safe="") from the Python manager's image.
        for (value, quoted) in [
            ("alice", "alice"),
            ("a b", "a%20b"),
            ("ä~-._", "%C3%A4~-._"),
            ("x/y:z@w", "x%2Fy%3Az%40w"),
            ("%", "%25"),
            ("日本", "%E6%97%A5%E6%9C%AC"),
        ] {
            assert_eq!(quote(value), quoted);
        }
    }

    #[test]
    fn isoformat_round_trips_and_omits_zero_microseconds() {
        assert_eq!(isoformat(1_792_959_028, 123_456), "2026-10-25T20:10:28.123456+00:00");
        assert_eq!(isoformat(1_792_959_028, 0), "2026-10-25T20:10:28+00:00");
        assert_eq!(fromisoformat_timestamp("2026-10-25T20:10:28.123456+00:00"), Some(1_792_959_028.123456));
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 2, 29), 11_016);
        assert_eq!(backup_stamp().len(), "20261025T201028.123456Z".len());
        assert_eq!(token_urlsafe(18).len(), 24);
    }

    #[test]
    fn fromisoformat_matches_python_313() {
        // datetime.fromisoformat(value).timestamp() from python:3.13.5 (None = ValueError).
        let vectors: [(&str, Option<f64>); 20] = [
            ("2000-01-01T00:00:00+00:00", Some(946684800.0)),
            ("2026-10-25T20:10:28.123456+00:00", Some(1792959028.123456)),
            ("2026-10-25T20:10:28+00:00", Some(1792959028.0)),
            ("2026-10-25", Some(1792886400.0)),
            ("2026-10-25T20:10", Some(1792959000.0)),
            ("2026-10-25 20:10:28Z", Some(1792959028.0)),
            ("2026-10-25T20:10:28.5+03:00", Some(1792948228.5)),
            ("20261025T201028Z", Some(1792959028.0)),
            ("2026-10-25T20", Some(1792958400.0)),
            ("2026-10-25T20:10:28,123+0130", Some(1792953628.123)),
            ("2026-W43-7", Some(1792886400.0)),
            ("bad", None),
            ("2026-13-01", None),
            ("2026-10-25T25:00", None),
            ("2026-10-25T20:10:28.1234567+00:00", Some(1792959028.123456)),
            ("2026-10-25T20:10:28-05", Some(1792977028.0)),
            ("2026-02-29", None),
            ("2024-02-29T00:00:00+00:00", Some(1709164800.0)),
            ("2026-10-25T24:00:00+00:00", None),
            ("2026-10-25T20:10:28.12+00:00", Some(1792959028.12)),
        ];
        for (text, expected) in vectors {
            let got = fromisoformat_timestamp(text);
            match (got, expected) {
                (Some(a), Some(b)) => assert!((a - b).abs() < 1e-6, "{text}: {a} != {b}"),
                (a, b) => assert_eq!(a, b, "{text}"),
            }
        }
    }

    #[test]
    fn reentrant_mutex_admits_its_owner_and_blocks_others() {
        let lock = std::sync::Arc::new(ReentrantMutex::default());
        let outer = lock.lock();
        let inner = lock.lock();
        let other = {
            let lock = lock.clone();
            std::thread::spawn(move || {
                let _guard = lock.lock();
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!other.is_finished());
        drop(inner);
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(!other.is_finished());
        drop(outer);
        other.join().unwrap();
    }
}
