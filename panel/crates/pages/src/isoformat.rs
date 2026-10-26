//! `datetime.fromisoformat(text)` of CPython 3.13 (`Modules/_datetimemodule.c`), reduced to what
//! the `UserLimits.expiration_rfc3339` validator asks: does the text parse, and does it carry an
//! offset. A line-for-line port of the C parser — it works on the UTF-8 bytes with a trailing NUL,
//! as the C code does, so its corner cases (the separator may be any Unicode character, `HHMM`
//! without colons, ISO week dates, a fraction of any length) are Python's.
//!
//! Checked against `tests/fixtures/fromisoformat.json`, recorded from Python 3.13.5.

/// What `fromisoformat` made of a text it accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parsed {
    /// `tzinfo` is set.
    Aware,
    /// No offset.
    Naive,
}

/// The text is not an ISO 8601 date-time Python accepts (`ValueError`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invalid;

struct Bytes<'a>(&'a [u8]);

impl Bytes<'_> {
    /// `dtstr[i]`, NUL at and past the end (the C string's terminator).
    fn at(&self, index: usize) -> u8 {
        self.0.get(index).copied().unwrap_or(0)
    }

    /// `parse_digits(p, &var, n)`: the next position, or `None` on a non-digit.
    fn digits(&self, mut position: usize, count: usize, var: &mut i64) -> Option<usize> {
        for _ in 0..count {
            let byte = self.at(position);
            position += 1;
            if !byte.is_ascii_digit() {
                return None;
            }
            *var = *var * 10 + i64::from(byte - b'0');
        }
        Some(position)
    }
}

/// `datetime.fromisoformat(text)`: whether it parses, and with or without an offset.
pub fn fromisoformat(text: &str) -> Result<Parsed, Invalid> {
    // `_sanitize_isoformat_str`: every valid string is at least 7 characters long.
    if text.chars().count() < 7 {
        return Err(Invalid);
    }
    let bytes = Bytes(text.as_bytes());
    let len = text.len();
    let separator = find_separator(&bytes, len).ok_or(Invalid)?;
    let (year, month, day) = parse_date(&bytes, separator).ok_or(Invalid)?;
    let mut time = Time::default();
    let mut aware = false;
    if len > separator {
        // Skip one Unicode character; the time runs to the end of the string.
        let separator_len = text[separator..].chars().next().ok_or(Invalid)?.len_utf8();
        let found = parse_time(&bytes, separator + separator_len, len).ok_or(Invalid)?;
        aware = found.1;
        time = found.0;
    }
    // `new_datetime`'s range checks.
    let valid = (1..=9999).contains(&year)
        && (1..=12).contains(&month)
        && day >= 1
        && day <= days_in_month(year, month)
        && (0..=23).contains(&time.hour)
        && (0..=59).contains(&time.minute)
        && (0..=59).contains(&time.second)
        && (0..=999_999).contains(&time.microsecond);
    if !valid {
        return Err(Invalid);
    }
    Ok(if aware { Parsed::Aware } else { Parsed::Naive })
}

/// `_find_isoformat_datetime_separator`: where the date ends; `None` for C's `-1`.
fn find_separator(bytes: &Bytes<'_>, len: usize) -> Option<usize> {
    if len == 7 {
        return Some(7);
    }
    if bytes.at(4) == b'-' {
        if bytes.at(5) == b'W' {
            if len < 8 {
                return None;
            }
            if len > 8 && bytes.at(8) == b'-' {
                if len == 9 {
                    return None;
                }
                if len > 10 && bytes.at(10).is_ascii_digit() {
                    return Some(8);
                }
                return Some(10);
            }
            return Some(8);
        }
        return Some(10);
    }
    if bytes.at(4) == b'W' {
        let mut index = 7;
        while index < len && bytes.at(index).is_ascii_digit() {
            index += 1;
        }
        if index < 9 {
            return Some(index);
        }
        return Some(if index % 2 == 0 { 7 } else { 8 });
    }
    Some(8)
}

/// `parse_isoformat_date(dtstr, len)`: `(year, month, day)` — not yet range-checked.
fn parse_date(bytes: &Bytes<'_>, len: usize) -> Option<(i64, i64, i64)> {
    let mut year = 0;
    let mut position = bytes.digits(0, 4, &mut year)?;
    let uses_separator = bytes.at(position) == b'-';
    if uses_separator {
        position += 1;
    }
    if bytes.at(position) == b'W' {
        position += 1;
        let mut week = 0;
        position = bytes.digits(position, 2, &mut week)?;
        let mut weekday = 0;
        if position < len {
            if uses_separator {
                let separator = bytes.at(position);
                position += 1;
                if separator != b'-' {
                    return None;
                }
            }
            bytes.digits(position, 1, &mut weekday)?;
        } else {
            weekday = 1;
        }
        return iso_to_ymd(year, week, weekday);
    }
    let mut month = 0;
    position = bytes.digits(position, 2, &mut month)?;
    if uses_separator {
        let separator = bytes.at(position);
        position += 1;
        if separator != b'-' {
            return None;
        }
    }
    let mut day = 0;
    bytes.digits(position, 2, &mut day)?;
    Some((year, month, day))
}

#[derive(Debug, Default, Clone, Copy)]
struct Time {
    hour: i64,
    minute: i64,
    second: i64,
    microsecond: i64,
}

/// `parse_hh_mm_ss_ff(tstr, tstr_end, …)`: `Ok(true)` when something follows the time (C's 1),
/// `Ok(false)` at the end, `Err` on a malformed time.
fn parse_hh_mm_ss_ff(bytes: &Bytes<'_>, start: usize, end: usize, time: &mut Time) -> Result<bool, ()> {
    *time = Time::default();
    let mut position = start;
    let mut has_separator = true;
    let mut fractional_component = 2;
    for index in 0..3 {
        let mut value = 0;
        position = bytes.digits(position, 2, &mut value).ok_or(())?;
        match index {
            0 => time.hour = value,
            1 => time.minute = value,
            _ => time.second = value,
        }
        let c = bytes.at(position);
        position += 1;
        if index == 0 {
            has_separator = c == b':';
        }
        if position >= end {
            return Ok(c != 0);
        } else if has_separator && c == b':' {
            if index < 2 {
                continue;
            }
            // Python also accepts a colon as the seconds' decimal mark.
            break;
        } else if c == b'.' || c == b',' {
            fractional_component = index;
            break;
        } else if !has_separator {
            position -= 1;
        } else {
            return Err(()); // malformed time separator
        }
    }
    // The fraction: up to six digits count, the rest are skipped.
    let remains = end.saturating_sub(position);
    let to_parse = remains.min(6);
    let mut microsecond = 0;
    position = bytes.digits(position, to_parse, &mut microsecond).ok_or(())?;
    const CORRECTION: [i64; 5] = [100_000, 10_000, 1_000, 100, 10];
    if to_parse < 6 {
        // C indexes `correction[to_parse - 1]`; with nothing left to parse `to_parse` is 0 and the
        // loop above never ran (`position >= end` returned first).
        microsecond *= CORRECTION.get(to_parse.wrapping_sub(1)).copied().unwrap_or(1);
    }
    match fractional_component {
        0 => {
            let within_hour = microsecond * 3_600;
            time.minute = within_hour / 60_000_000;
            time.second = (within_hour / 1_000_000) % 60;
            time.microsecond = within_hour % 1_000_000;
        }
        1 => {
            let within_minute = microsecond * 60;
            time.second = within_minute / 1_000_000;
            time.microsecond = within_minute % 1_000_000;
        }
        _ => time.microsecond = microsecond,
    }
    while bytes.at(position).is_ascii_digit() {
        position += 1;
    }
    Ok(bytes.at(position) != 0)
}

/// `parse_isoformat_time(dtstr, dtlen, …)`: the time and whether an offset was given.
fn parse_time(bytes: &Bytes<'_>, start: usize, end: usize) -> Option<(Time, bool)> {
    let mut tz_position = start;
    loop {
        let byte = bytes.at(tz_position);
        if byte == b'Z' || byte == b'+' || byte == b'-' {
            break;
        }
        tz_position += 1;
        if tz_position >= end {
            break;
        }
    }
    let mut time = Time::default();
    let more = parse_hh_mm_ss_ff(bytes, start, tz_position, &mut time).ok()?;
    if tz_position == end {
        // No offset: anything left at the end is an error.
        return (!more).then_some((time, false));
    }
    if bytes.at(tz_position) == b'Z' {
        return (bytes.at(tz_position + 1) == 0).then_some((time, true));
    }
    let mut offset = Time::default();
    let rest = parse_hh_mm_ss_ff(bytes, tz_position + 1, end, &mut offset);
    // `tzinfo_from_isoformat_results` constructs a timedelta first: minutes/seconds
    // may overflow their clock ranges, provided the normalized offset stays below 24h.
    let seconds = offset.hour * 3_600 + offset.minute * 60 + offset.second;
    if seconds >= 86_400 {
        return None;
    }
    match rest {
        Ok(false) => Some((time, true)),
        _ => None,
    }
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// `days_in_month(year, month)` (0 for a month outside 1..12, like C's table entry 0).
fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// `days_before_year(year)`: days in the years before `year` (proleptic Gregorian).
fn days_before_year(year: i64) -> i64 {
    let y = year - 1;
    y * 365 + y.div_euclid(4) - y.div_euclid(100) + y.div_euclid(400)
}

/// `ymd_to_ord(year, month, day)`.
fn ymd_to_ord(year: i64, month: i64, day: i64) -> i64 {
    let before_month: i64 = (1..month).map(|m| days_in_month(year, m)).sum();
    days_before_year(year) + before_month + day
}

/// `ord_to_ymd(ordinal)`.
fn ord_to_ymd(ordinal: i64) -> (i64, i64, i64) {
    let mut n = ordinal - 1;
    let n400 = n.div_euclid(146_097);
    n = n.rem_euclid(146_097);
    let mut year = n400 * 400 + 1;
    let n100 = n / 36_524;
    n %= 36_524;
    let n4 = n / 1_461;
    n %= 1_461;
    let n1 = n / 365;
    n %= 365;
    year += n100 * 100 + n4 * 4 + n1;
    if n1 == 4 || n100 == 4 {
        return (year - 1, 12, 31);
    }
    let mut month = 1;
    while n >= days_in_month(year, month) {
        n -= days_in_month(year, month);
        month += 1;
    }
    (year, month, n + 1)
}

/// `iso_week1_monday(year)`.
fn iso_week1_monday(year: i64) -> i64 {
    let first_day = ymd_to_ord(year, 1, 1);
    let first_weekday = (first_day + 6).rem_euclid(7);
    let mut week1_monday = first_day - first_weekday;
    if first_weekday > 3 {
        week1_monday += 7;
    }
    week1_monday
}

/// `iso_to_ymd(iso_year, iso_week, iso_day)`; `None` when C returns an error.
fn iso_to_ymd(iso_year: i64, iso_week: i64, iso_day: i64) -> Option<(i64, i64, i64)> {
    if !(1..=9999).contains(&iso_year) {
        return None;
    }
    if iso_week <= 0 || iso_week >= 53 {
        let mut out_of_range = true;
        if iso_week == 53 {
            // A year has 53 ISO weeks when it starts on a Thursday, or on a Wednesday in a leap year.
            let first_weekday = (ymd_to_ord(iso_year, 1, 1) + 6).rem_euclid(7);
            if first_weekday == 3 || (first_weekday == 2 && is_leap(iso_year)) {
                out_of_range = false;
            }
        }
        if out_of_range {
            return None;
        }
    }
    if !(1..=7).contains(&iso_day) {
        return None;
    }
    let day_1 = iso_week1_monday(iso_year);
    let offset = (iso_week - 1) * 7 + iso_day - 1;
    Some(ord_to_ymd(day_1 + offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_python_3135_goldens() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/fromisoformat.json")).unwrap();
        let cases = fixture.as_array().unwrap();
        assert!(!cases.is_empty());
        for case in cases {
            let text = case["text"].as_str().unwrap();
            let expected = match case["result"].as_str().unwrap() {
                "aware" => Ok(Parsed::Aware),
                "naive" => Ok(Parsed::Naive),
                "invalid" => Err(Invalid),
                result => panic!("unknown result {result:?} for {text:?}"),
            };
            assert_eq!(fromisoformat(text), expected, "Python golden for {text:?}");
        }
    }

    #[test]
    fn rfc3339_forms_parse() {
        assert_eq!(fromisoformat("2027-01-01T00:00:00+00:00"), Ok(Parsed::Aware));
        assert_eq!(fromisoformat("2027-01-01T00:00:00"), Ok(Parsed::Naive));
        assert_eq!(fromisoformat("2027-01-01"), Ok(Parsed::Naive));
        assert_eq!(fromisoformat("2027-01-01 10:20:30.5+05:30"), Ok(Parsed::Aware));
        assert_eq!(fromisoformat("20270101T102030-0200"), Ok(Parsed::Aware));
        assert_eq!(fromisoformat("2027-W01-1T00:00+01:00"), Ok(Parsed::Aware));
        assert_eq!(fromisoformat("not a date"), Err(Invalid));
        assert_eq!(fromisoformat("2027-02-29T00:00:00+00:00"), Err(Invalid));
        assert_eq!(fromisoformat("2027-01-01T25:00:00+00:00"), Err(Invalid));
        assert_eq!(fromisoformat("2027-01-01T00:00:00+24:00"), Err(Invalid));
    }

    #[test]
    fn ordinals_round_trip() {
        for ordinal in [1, 365, 366, 730_120, 738_000, 3_652_059] {
            let (y, m, d) = ord_to_ymd(ordinal);
            assert_eq!(ymd_to_ord(y, m, d), ordinal);
        }
        assert_eq!(ord_to_ymd(1), (1, 1, 1));
        assert_eq!(ord_to_ymd(3_652_059), (9999, 12, 31));
    }
}
