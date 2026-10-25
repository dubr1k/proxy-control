//! The Caddyfile line patterns of the Python manager, as hand-written matchers with Python's
//! `re` semantics (`\s` is Unicode whitespace, `$` the end of the line).

use crate::pyutil::{is_space, lstrip};

/// `^\s*<word>(?:\s|$)`.
pub fn starts_with_word(line: &str, word: &str) -> bool {
    lstrip(line).strip_prefix(word).is_some_and(|rest| rest.chars().next().is_none_or(is_space))
}

/// `^\s*<word>\s+` and what follows the whitespace.
fn after_word_and_space<'a>(line: &'a str, word: &str) -> Option<&'a str> {
    let rest = lstrip(line).strip_prefix(word)?;
    if !rest.chars().next().is_some_and(is_space) {
        return None;
    }
    Some(lstrip(rest))
}

/// `^\s*basic_auth\s+`.
pub fn is_basic_auth(line: &str) -> bool {
    after_word_and_space(line, "basic_auth").is_some()
}

/// `^\s*basic_auth\s+(\S+)\s+(\S+)\s*$`.
pub fn basic_auth_pair(line: &str) -> Option<(&str, &str)> {
    let rest = after_word_and_space(line, "basic_auth")?;
    let mut tokens = rest.split(is_space).filter(|part| !part.is_empty());
    let (name, password) = (tokens.next()?, tokens.next()?);
    tokens.next().is_none().then_some((name, password))
}

/// `<word>\s*\{\s*(?:#.*)?` after optional leading whitespace, to the end of the line.
fn opens_block(line: &str, word: &str) -> bool {
    lstrip(line).strip_prefix(word).is_some_and(|rest| {
        lstrip(rest).strip_prefix('{').is_some_and(|tail| {
            let tail = lstrip(tail);
            tail.is_empty() || tail.starts_with('#')
        })
    })
}

/// `re.fullmatch(r"\s*forward_proxy\s*\{\s*(?:#.*)?", line)`.
pub fn is_forward_proxy_block(line: &str) -> bool {
    opens_block(line, "forward_proxy")
}

/// `^\s*acl\s*\{\s*(?:#.*)?$`.
pub fn is_acl_open(line: &str) -> bool {
    opens_block(line, "acl")
}

/// `re.match(r"^\s*route\s*\{", line)`.
pub fn is_route_start(line: &str) -> bool {
    lstrip(line).strip_prefix("route").is_some_and(|rest| lstrip(rest).starts_with('{'))
}

/// `^\s*upstream\s+(\S+)\s*(?:#.*)?$`: the URL, where a `#` inside the token may start the
/// comment when the rest of the token would not match otherwise.
pub fn upstream_target(line: &str) -> Option<&str> {
    let rest = after_word_and_space(line, "upstream")?;
    let run_end = rest.find(is_space).unwrap_or(rest.len());
    if run_end == 0 {
        return None;
    }
    let tail_ok = |tail: &str| {
        let tail = lstrip(tail);
        tail.is_empty() || tail.starts_with('#')
    };
    // Greedy first, then shorter tokens (the regex backtracks).
    let mut ends: Vec<usize> = rest[..run_end].char_indices().map(|(i, c)| i + c.len_utf8()).collect();
    ends.reverse();
    ends.into_iter().find(|&end| tail_ok(&rest[end..])).map(|end| &rest[..end])
}

/// `^\s*deny\s+(.+?)\s*$` → `group(1).split()`.
pub fn deny_subjects(line: &str) -> Option<Vec<&str>> {
    let rest = lstrip(line).strip_prefix("deny")?;
    let spaces = rest.chars().take_while(|c| is_space(*c)).count();
    if spaces == 0 {
        return None;
    }
    let remainder = lstrip(rest);
    if remainder.is_empty() && spaces < 2 {
        // `\s+` must leave at least one character for `.+?`.
        return None;
    }
    Some(crate::pyutil::split_whitespace(remainder))
}

/// `^\s*probe_resistance(?:\s|$)`.
pub fn is_probe_resistance(line: &str) -> bool {
    starts_with_word(line, "probe_resistance")
}

/// `re.sub(r"(?<=://)[^/@\s]+@", replacement, text)`.
pub fn sub_userinfo(text: &str, replacement: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(found) = rest.find("://") {
        let start = found + 3;
        out.push_str(&rest[..start]);
        rest = &rest[start..];
        let run = rest.find(|c: char| c == '/' || c == '@' || is_space(c)).unwrap_or(rest.len());
        if run > 0 && rest[run..].starts_with('@') {
            out.push_str(replacement);
            rest = &rest[run + 1..];
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_patterns_follow_python_re() {
        assert_eq!(basic_auth_pair("    basic_auth a b  "), Some(("a", "b")));
        assert_eq!(basic_auth_pair("basic_auth a"), None);
        assert_eq!(basic_auth_pair("basic_auth a b c"), None);
        assert_eq!(basic_auth_pair("basic_autha b"), None);
        assert!(is_basic_auth("  basic_auth {") && !is_basic_auth("basic_auth"));
        assert!(is_forward_proxy_block("  forward_proxy { # x") && !is_forward_proxy_block("forward_proxy"));
        assert!(
            starts_with_word("forward_proxy", "forward_proxy") && !starts_with_word("forward_proxyx", "forward_proxy")
        );
        assert_eq!(upstream_target("  upstream socks5://h:1  # c"), Some("socks5://h:1"));
        assert_eq!(upstream_target("upstream abc#def ghi"), Some("abc"));
        assert_eq!(upstream_target("upstream abc def"), None);
        assert_eq!(upstream_target("upstream abc#def #ghi"), Some("abc#def"));
        assert_eq!(upstream_target("upstream abc#def"), Some("abc#def"));
        assert_eq!(upstream_target("upstream abc#def x"), Some("abc"));
        assert_eq!(upstream_target("upstream"), None);
        assert_eq!(deny_subjects("deny a b "), Some(vec!["a", "b"]));
        assert_eq!(deny_subjects("deny "), None);
        assert_eq!(deny_subjects("deny  "), Some(vec![]));
        assert_eq!(deny_subjects("denyx"), None);
        assert!(is_route_start("  route{x") && !is_route_start("router {"));
    }

    #[test]
    fn userinfo_substitution_matches_the_lookbehind_pattern() {
        let line = "    upstream socks5://alice:s3cret@127.0.0.1:1080 # https://bob:pw@proxy.example:443/x";
        assert_eq!(
            sub_userinfo(line, "***@"),
            "    upstream socks5://***@127.0.0.1:1080 # https://***@proxy.example:443/x"
        );
        assert_eq!(sub_userinfo("socks5://u:p@h", ""), "socks5://h");
        assert_eq!(sub_userinfo("a://@b", ""), "a://@b");
        assert_eq!(sub_userinfo(":///x@y", "*"), ":///x@y");
    }
}
