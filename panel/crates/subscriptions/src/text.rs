//! Small pieces of Python's standard library the renderers rely on: `html.escape`, the `DEEPLINK`
//! guard (a `re` pattern with `IGNORECASE`), `datetime.strftime` of a UTC stamp, Python's `str()`
//! of a JSON value.

use panel_core::pytext;

/// `html.escape(text, quote=True)`: `&` first, then `<`, `>`, `"`, `'` (as `&#x27;`).
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

/// What `re.IGNORECASE` makes of a character for the ASCII letters of the pattern: ASCII folds to
/// lower case, and the four non-ASCII characters `re` treats as case variants of an ASCII letter
/// (KELVIN SIGN ~ k, LONG S ~ s, DOTTED CAPITAL I and DOTLESS SMALL I ~ i).
fn fold(ch: char) -> char {
    match ch {
        '\u{212A}' => 'k',
        '\u{17F}' => 's',
        '\u{130}' | '\u{131}' => 'i',
        _ => ch.to_ascii_lowercase(),
    }
}

/// `DEEPLINK.match(text)` for
/// `^(?!javascript:|data:|vbscript:)[a-z][a-z0-9+.-]*://[^\s"'<>]+$` with `re.IGNORECASE`: an app
/// scheme, never `javascript:`/`data:`/`vbscript:`, no whitespace, quotes or angle brackets — and,
/// as `$` does, a single final `\n` is allowed.
pub fn is_deep_link(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let folded: Vec<char> = chars.iter().map(|ch| fold(*ch)).collect();
    for refused in ["javascript:", "data:", "vbscript:"] {
        if folded.len() >= refused.len() && folded.iter().zip(refused.chars()).all(|(a, b)| *a == b) {
            return false;
        }
    }
    let Some(first) = folded.first() else { return false };
    if !first.is_ascii_lowercase() {
        return false;
    }
    let mut index = 1;
    while index < folded.len() && (folded[index].is_ascii_lowercase() || folded[index].is_ascii_digit() || "+.-".contains(folded[index])) {
        index += 1;
    }
    if chars.get(index..index + 3) != Some(&[':', '/', '/'][..]) {
        return false;
    }
    let rest = &chars[index + 3..];
    let rest = match rest.split_last() {
        Some(('\n', body)) => body,
        _ => rest,
    };
    !rest.is_empty() && rest.iter().all(|ch| !pytext::is_space(*ch) && !matches!(ch, '"' | '\'' | '<' | '>'))
}

/// `datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")`.
pub fn utc_minute(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let second_of_day = seconds.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {:02}:{:02} UTC", second_of_day / 3600, second_of_day % 3600 / 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_matches_html_escape() {
        assert_eq!(escape("Sergey <b>&</b> O'Brien \"x\""), "Sergey &lt;b&gt;&amp;&lt;/b&gt; O&#x27;Brien &quot;x&quot;");
    }

    #[test]
    fn the_deep_link_guard_matches_the_python_pattern() {
        for good in ["tg://proxy?server=a&port=443", "KARING://x", "mierus://u:p@h?x=1", "tt://?AAA", "a://b\n"] {
            assert!(is_deep_link(good), "{good}");
        }
        for bad in [
            "javascript:alert(1)",
            "JavaScript://x",
            "data:text/html,<b>x</b>",
            "vbscript://x",
            "tg://x\" onmouseover=\"alert(1)",
            "1tg://x",
            "tg://",
            "tg:/x",
            "tg://a b",
            "tg://a\u{a0}b",
            "tg://x\n\n",
            "javaſcript://x",
            "",
        ] {
            assert!(!is_deep_link(bad), "{bad:?}");
        }
        assert!(is_deep_link("\u{212A}aring://x"));
    }

    #[test]
    fn utc_minutes_match_strftime() {
        assert_eq!(utc_minute(1_800_000_000), "2027-01-15 08:00 UTC");
        assert_eq!(utc_minute(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc_minute(951_782_400), "2000-02-29 00:00 UTC");
        assert_eq!(utc_minute(1_793_005_853), "2026-10-26 09:10 UTC");
        assert_eq!(utc_minute(-1), "1969-12-31 23:59 UTC");
    }
}
