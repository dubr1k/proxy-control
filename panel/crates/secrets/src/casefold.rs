//! `str.casefold()` where the result is matched against ASCII text.
//!
//! Python's full case folding differs from lowercasing for a few characters. The ones whose fold
//! contains ASCII — and so can complete an ASCII word such as `secret` — are listed below, taken
//! from Python 3.13 (Unicode 15.1) and checked against it by the tests; every other character is
//! lowercased, which never yields ASCII from a non-ASCII character. The result therefore has
//! exactly Python's ASCII characters at exactly Python's places; non-ASCII characters outside the
//! table may fold differently (final sigma, Cherokee, …), which no ASCII match can observe.
//!
//! Belongs in `panel_core::pytext` next to `lower`.

/// Non-ASCII characters whose full case fold contains ASCII (`CaseFolding.txt` status F and K).
const ASCII_FOLDS: [(char, &str); 19] = [
    ('\u{df}', "ss"),
    ('\u{130}', "i\u{307}"),
    ('\u{149}', "\u{2bc}n"),
    ('\u{17f}', "s"),
    ('\u{1f0}', "j\u{30c}"),
    ('\u{1e96}', "h\u{331}"),
    ('\u{1e97}', "t\u{308}"),
    ('\u{1e98}', "w\u{30a}"),
    ('\u{1e99}', "y\u{30a}"),
    ('\u{1e9a}', "a\u{2be}"),
    ('\u{1e9e}', "ss"),
    ('\u{212a}', "k"),
    ('\u{fb00}', "ff"),
    ('\u{fb01}', "fi"),
    ('\u{fb02}', "fl"),
    ('\u{fb03}', "ffi"),
    ('\u{fb04}', "ffl"),
    ('\u{fb05}', "st"),
    ('\u{fb06}', "st"),
];

/// `text.casefold()`, exact wherever the fold contains ASCII (see the module docs).
pub fn casefold_for_ascii_match(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_ascii() {
            out.push(ch.to_ascii_lowercase());
        } else if let Some((_, folded)) = ASCII_FOLDS.iter().find(|(from, _)| *from == ch) {
            out.push_str(folded);
        } else {
            out.extend(ch.to_lowercase());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_the_special_characters_like_python() {
        assert_eq!(casefold_for_ascii_match("ſecret"), "secret");
        assert_eq!(casefold_for_ascii_match("STRAẞE"), "strasse");
        assert_eq!(casefold_for_ascii_match("ﬅoken"), "stoken");
        assert_eq!(casefold_for_ascii_match("secreẗ"), "secret\u{308}");
        assert_eq!(casefold_for_ascii_match("Ｓｅｃｒｅｔ"), "ｓｅｃｒｅｔ");
    }
}
