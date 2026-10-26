//! Hand-written equivalents of the installer's secret regexes (no regex crate, host inventory
//! §10.1), with Python's `re.IGNORECASE` semantics for `str` patterns: besides ASCII case,
//! `k` matches the Kelvin sign, `s` the long s and `i` both `İ` and dotless `ı`.
//!
//! | Function | Python |
//! |---|---|
//! | [`plan_text_has_secret`] | `planner._SECRET_ASSIGNMENT.search` |
//! | [`plan_key_is_secret`] | the key test of `planner._assert_secret_free` |
//! | [`report_text_names_secret`] | `report._SECRET_NAME.search` |
//! | [`redact`] | `cli._SECRET_ASSIGNMENT.sub(r"\1\2[REDACTED]", …)` |

use crate::pystr::{is_space, is_word_char, lower};

fn ci(c: char, ascii_lower: char) -> bool {
    if c.to_ascii_lowercase() == ascii_lower {
        return true;
    }
    matches!((ascii_lower, c), ('k', '\u{212a}') | ('s', '\u{17f}') | ('i', '\u{130}') | ('i', '\u{131}'))
}

fn literal(chars: &[char], pos: usize, word: &str) -> Option<usize> {
    let mut index = pos;
    for expected in word.chars() {
        if !chars.get(index).is_some_and(|c| ci(*c, expected)) {
            return None;
        }
        index += 1;
    }
    Some(index)
}

/// `private[_ -]?key` / `api[_ -]?key`.
fn with_separator(chars: &[char], pos: usize, head: &str) -> Option<usize> {
    let after = literal(chars, pos, head)?;
    if matches!(chars.get(after), Some('_' | ' ' | '-')) {
        if let Some(end) = literal(chars, after + 1, "key") {
            return Some(end);
        }
    }
    literal(chars, after, "key")
}

/// The end of a secret name at `pos` (`password|passwd|secret|token|private[_ -]?key|api[_ -]?key`,
/// plus `cookie|uuid` for the public report).
fn name_end(chars: &[char], pos: usize, report: bool) -> Option<usize> {
    for word in ["password", "passwd", "secret", "token"] {
        if let Some(end) = literal(chars, pos, word) {
            return Some(end);
        }
    }
    if let Some(end) = with_separator(chars, pos, "private").or_else(|| with_separator(chars, pos, "api")) {
        return Some(end);
    }
    if report {
        for word in ["cookie", "uuid"] {
            if let Some(end) = literal(chars, pos, word) {
                return Some(end);
            }
        }
    }
    None
}

fn skip_space(chars: &[char], mut pos: usize) -> usize {
    while chars.get(pos).is_some_and(|c| is_space(*c)) {
        pos += 1;
    }
    pos
}

/// `--name(=|\s+)("…"|'…'|\S+)` or `["']?name["']?\s*[:=]\s*("…"|'…'|[^\s,}\]]+)` anywhere.
pub fn plan_text_has_secret(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    (0..chars.len()).any(|pos| {
        if let Some(end) = name_end(&chars, pos, false) {
            // Flag form: `--password value` / `--password=value`.
            if pos >= 2 && chars[pos - 2] == '-' && chars[pos - 1] == '-' {
                let value = match chars.get(end) {
                    Some('=') => Some(end + 1),
                    Some(c) if is_space(*c) => Some(skip_space(&chars, end)),
                    _ => None,
                };
                if value.is_some_and(|v| chars.get(v).is_some_and(|c| !is_space(*c))) {
                    return true;
                }
            }
            // Assignment form: `password = value`, `"token": value`.
            let mut after = end;
            if matches!(chars.get(after), Some('"' | '\'')) {
                after += 1;
            }
            after = skip_space(&chars, after);
            if matches!(chars.get(after), Some(':' | '=')) {
                let value = skip_space(&chars, after + 1);
                if chars.get(value).is_some_and(|c| !is_space(*c) && !matches!(c, ',' | '}' | ']')) {
                    return true;
                }
            }
        }
        false
    })
}

/// A mapping key the plan must not carry: lowercased, reduced to `[a-z0-9]`, it contains
/// `password`, `passwd`, `secret`, `token`, `privatekey` or `apikey`.
pub fn plan_key_is_secret(key: &str) -> bool {
    let compact: String = lower(key).chars().filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit()).collect();
    ["password", "passwd", "secret", "token", "privatekey", "apikey"].iter().any(|part| compact.contains(part))
}

/// `(?i)(password|passwd|secret|token|private[_ -]?key|api[_ -]?key|cookie|uuid)` anywhere.
pub fn report_text_names_secret(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    (0..chars.len()).any(|pos| name_end(&chars, pos, true).is_some())
}

/// Replaces the value of every `name[:=]value` assignment (after a word boundary) with
/// `[REDACTED]`, keeping the name and the separator as written.
pub fn redact(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut pos = 0;
    while pos < chars.len() {
        if let Some((name_stop, value_start, value_stop)) = redaction_at(&chars, pos) {
            out.extend(&chars[pos..name_stop]);
            out.extend(&chars[name_stop..value_start]);
            out.push_str("[REDACTED]");
            pos = value_stop;
            continue;
        }
        out.push(chars[pos]);
        pos += 1;
    }
    out
}

fn redaction_at(chars: &[char], pos: usize) -> Option<(usize, usize, usize)> {
    if pos > 0 && is_word_char(chars[pos - 1]) {
        return None;
    }
    let name_stop = name_end(chars, pos, false)?;
    let separator = skip_space(chars, name_stop);
    if !matches!(chars.get(separator), Some(':' | '=')) {
        return None;
    }
    let value_start = skip_space(chars, separator + 1);
    let first = *chars.get(value_start)?;
    if first == '"' || first == '\'' {
        if let Some(offset) = chars[value_start + 1..].iter().position(|c| *c == first) {
            return Some((name_stop, value_start, value_start + offset + 2));
        }
    }
    if is_space(first) {
        return None;
    }
    let mut stop = value_start;
    while chars.get(stop).is_some_and(|c| !is_space(*c)) {
        stop += 1;
    }
    Some((name_stop, value_start, stop))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_scanner_matches_python_examples() {
        assert!(plan_text_has_secret("write password=hunter2"));
        assert!(plan_text_has_secret("bootstrap --password hunter2"));
        assert!(plan_text_has_secret("write settings {\"token\":\"abc\"}"));
        assert!(plan_text_has_secret("PRIVATE KEY: x"));
        assert!(plan_text_has_secret("api-key=x"));
        assert!(plan_text_has_secret("--password=\"a b\""));
        assert!(!plan_text_has_secret("verify the password login mechanism is disabled"));
        assert!(!plan_text_has_secret("token=,x"));
        assert!(!plan_text_has_secret("--password"));
        assert!(!plan_text_has_secret("passwords=1"));
        assert!(plan_text_has_secret("to\u{212a}en=1"));
    }

    #[test]
    fn keys_and_report_names() {
        assert!(plan_key_is_secret("Private-Key"));
        assert!(plan_key_is_secret("mcp_token"));
        assert!(!plan_key_is_secret("ports"));
        assert!(report_text_names_secret("the panel password is stored in the handoff"));
        assert!(report_text_names_secret("UUID"));
        assert!(!report_text_names_secret("compose files: compose.yaml"));
    }

    #[test]
    fn redaction_matches_python() {
        assert_eq!(redact("SafeError: password=hunter2"), "SafeError: password=[REDACTED]");
        assert_eq!(redact("token: \"a b\" tail"), "token: [REDACTED] tail");
        assert_eq!(redact("x_password=1"), "x_password=1");
        assert_eq!(redact("Api Key = abc, Secret:x"), "Api Key = [REDACTED] Secret:[REDACTED]");
        assert_eq!(redact("password= "), "password= ");
        assert_eq!(redact("secret='open"), "secret=[REDACTED]");
    }
}
