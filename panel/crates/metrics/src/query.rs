//! Query parameters the way FastAPI reads them for these routes: Starlette's
//! `parse_qsl(keep_blank_values=True)` (the last value of a repeated name wins) and pydantic's
//! lax `int` from a string with `ge`/`le` bounds. Error shapes are checked against
//! `tests/fixtures/routes.json`.

use std::collections::HashMap;

use panel_core::errors::{LocItem, ValidationIssue};
use panel_core::pytext;
use serde_json::{json, Map, Value};

/// The decoded parameters of a query string (last value wins).
#[derive(Debug, Clone, Default)]
pub struct Query {
    values: HashMap<String, String>,
}

impl Query {
    pub fn parse(raw: Option<&str>) -> Self {
        let mut values = HashMap::new();
        for field in raw.unwrap_or("").split('&') {
            if field.is_empty() {
                continue;
            }
            let (name, value) = field.split_once('=').unwrap_or((field, ""));
            let decode = |text: &str| pytext::unquote(&text.replace('+', " "));
            values.insert(decode(name), decode(value));
        }
        Self { values }
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }
}

fn loc(name: &str) -> Vec<LocItem> {
    vec!["query".into(), name.into()]
}

/// A required `str` parameter.
pub fn required(query: &Query, name: &str, issues: &mut Vec<ValidationIssue>) -> Option<String> {
    match query.get(name) {
        Some(value) => Some(value.to_string()),
        None => {
            issues.push(ValidationIssue::missing(loc(name), Value::Null));
            None
        }
    }
}

/// What pydantic-core's `str_as_int` makes of a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Parsed {
    Int(i64),
    /// An integer beyond `i64` (pydantic keeps it as a big int); only its sign matters here.
    Big {
        negative: bool,
    },
}

fn parse_digits(text: &str) -> Option<Parsed> {
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    match text.parse::<i64>() {
        Ok(value) => Some(Parsed::Int(value)),
        Err(_) => Some(Parsed::Big { negative }),
    }
}

/// Python's underscore rule: single underscores between digits only.
fn strip_underscores(text: &str) -> Option<String> {
    let body = text.trim_start_matches(['+', '-']);
    if body.starts_with('_') || body.ends_with('_') || body.contains("__") {
        return None;
    }
    Some(text.replace('_', ""))
}

fn str_as_int(text: &str) -> Option<Parsed> {
    let attempt = |candidate: &str| {
        parse_digits(candidate).or_else(|| {
            if candidate.contains('_') {
                strip_underscores(candidate).and_then(|plain| parse_digits(&plain))
            } else {
                None
            }
        })
    };
    let text = text.trim();
    attempt(text).or_else(|| {
        let (whole, fraction) = text.split_once('.')?;
        (!fraction.is_empty() && fraction.bytes().all(|b| b == b'0')).then_some(whole).and_then(attempt)
    })
}

/// An `int` parameter with a default and `ge`/`le` bounds; `None` after recording an issue.
pub fn bounded_int(
    query: &Query,
    name: &str,
    default: i64,
    ge: i64,
    le: i64,
    issues: &mut Vec<ValidationIssue>,
) -> Option<i64> {
    let Some(raw) = query.get(name) else {
        return Some(default);
    };
    let input = Value::String(raw.to_string());
    if raw.trim().len() > 4300 {
        issues.push(ValidationIssue::new(
            "int_parsing_size",
            loc(name),
            "Unable to parse input string as an integer, exceeded maximum size",
            input,
        ));
        return None;
    }
    let bound = |kind: &str, word: &str, key: &str, limit: i64| {
        let mut ctx = Map::new();
        ctx.insert(key.into(), json!(limit));
        ValidationIssue::new(kind, loc(name), format!("Input should be {word} {limit}"), input.clone()).with_ctx(ctx)
    };
    let too_small = || bound("greater_than_equal", "greater than or equal to", "ge", ge);
    let too_large = || bound("less_than_equal", "less than or equal to", "le", le);
    match str_as_int(raw) {
        None => {
            issues.push(ValidationIssue::int_parsing(loc(name), input.clone()));
            None
        }
        Some(Parsed::Big { negative: true }) => {
            issues.push(too_small());
            None
        }
        Some(Parsed::Big { negative: false }) => {
            issues.push(too_large());
            None
        }
        Some(Parsed::Int(value)) if value < ge => {
            issues.push(too_small());
            None
        }
        Some(Parsed::Int(value)) if value > le => {
            issues.push(too_large());
            None
        }
        Some(Parsed::Int(value)) => Some(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_value_wins_and_blank_values_are_kept() {
        let query = Query::parse(Some("series=a&series=b+c&range=&x&points=%2B300"));
        assert_eq!(query.get("series"), Some("b c"));
        assert_eq!(query.get("range"), Some(""));
        assert_eq!(query.get("x"), Some(""));
        assert_eq!(query.get("points"), Some("+300"));
        assert_eq!(query.get("node"), None);
    }

    #[test]
    fn integers_like_pydantic() {
        for (text, want) in [
            ("300", Some(Parsed::Int(300))),
            ("+300", Some(Parsed::Int(300))),
            (" 300 ", Some(Parsed::Int(300))),
            ("0300", Some(Parsed::Int(300))),
            ("1_000", Some(Parsed::Int(1000))),
            ("300.0", Some(Parsed::Int(300))),
            ("300.00", Some(Parsed::Int(300))),
            ("1_000.0", Some(Parsed::Int(1000))),
            ("+300.0", Some(Parsed::Int(300))),
            ("-1_0", Some(Parsed::Int(-10))),
            ("0_1", Some(Parsed::Int(1))),
            ("\u{a0}300", Some(Parsed::Int(300))),
            ("\u{2003}300", Some(Parsed::Int(300))),
            ("-99999999999999999999", Some(Parsed::Big { negative: true })),
            ("300.", None),
            (".0", None),
            ("+_1", None),
            ("3_", None),
            ("1 0", None),
            ("+-1", None),
            ("--1", None),
            ("\u{663}", None),
            ("-1", Some(Parsed::Int(-1))),
            ("99999999999999999999", Some(Parsed::Big { negative: false })),
            ("1.5", None),
            ("2e2", None),
            ("0x10", None),
            ("", None),
            ("_1", None),
            ("1__0", None),
            ("１２", None),
        ] {
            assert_eq!(str_as_int(text), want, "{text:?}");
        }
    }
}
