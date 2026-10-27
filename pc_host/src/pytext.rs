//! Python string forms that leak into messages and bytes: `repr(str)`, `str(Path)`,
//! `str.title()`, and text-mode subprocess decoding.

use std::path::{Component, Path};

/// `repr(text)` for a Python `str`: single quotes unless the text holds a single quote and no
/// double quote; `\\`, the quote, `\t`, `\n`, `\r` escaped; other non-printable characters as
/// `\xNN`, `\uNNNN` or `\UNNNNNNNN`.
///
/// Printability outside Latin-1 is approximated: C0/C1 controls, DEL, the Unicode separators
/// and format characters commonly met (`U+00A0`, `U+00AD`, `U+2000`–`U+200F`, `U+2028`–`U+202F`,
/// `U+205F`–`U+206F`, `U+3000`, `U+FEFF`) and noncharacters `U+FFFE`/`U+FFFF` are escaped; every
/// other character is kept, as CPython keeps every printable one.
pub fn py_repr(text: &str) -> String {
    pc_common::pytext::repr_with_printable(text, printable)
}

fn printable(c: char) -> bool {
    let code = c as u32;
    if code < 0x20 || code == 0x7f || (0x80..=0xa0).contains(&code) || code == 0xad {
        return false;
    }
    !matches!(
        code,
        0x2000..=0x200f | 0x2028..=0x202f | 0x205f..=0x206f | 0x3000 | 0xfeff | 0xfffe | 0xffff | 0xd800..=0xdfff
    )
}

/// `str(PurePosixPath(path))`: repeated slashes collapsed, `.` components dropped, no trailing
/// slash, `.` for an empty relative path.
pub fn py_path_str(path: &Path) -> String {
    let mut out = String::new();
    let mut absolute = false;
    let mut parts: Vec<String> = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => absolute = true,
            Component::CurDir => {}
            Component::ParentDir => parts.push("..".into()),
            Component::Normal(name) => parts.push(name.to_string_lossy().into_owned()),
            Component::Prefix(_) => {}
        }
    }
    if absolute {
        out.push('/');
    }
    out.push_str(&parts.join("/"));
    if out.is_empty() {
        out.push('.');
    }
    out
}

/// `str.title()` for header names (`{k.title(): v}` in `version_agent/upstream.py`): a cased
/// letter after an uncased character is upper case, after a cased one lower case.
pub fn py_title(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut previous_cased = false;
    for ch in text.chars() {
        if ch.is_alphabetic() {
            if previous_cased {
                out.extend(ch.to_lowercase());
            } else {
                out.extend(ch.to_uppercase());
            }
            previous_cased = true;
        } else {
            out.push(ch);
            previous_cased = false;
        }
    }
    out
}

/// What `subprocess.run(…, text=True)` hands back: UTF-8 decoded (here with replacement, where
/// Python would raise) and universal newlines (`\r\n` and `\r` become `\n`).
pub fn text_mode(bytes: &[u8]) -> String {
    let decoded = String::from_utf8_lossy(bytes);
    if !decoded.contains('\r') {
        return decoded.into_owned();
    }
    decoded.replace("\r\n", "\n").replace('\r', "\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_common::pytext::{head_chars, tail_chars};

    #[test]
    fn repr_matches_python() {
        assert_eq!(py_repr("plain"), "'plain'");
        assert_eq!(py_repr("it's"), "\"it's\"");
        assert_eq!(py_repr("both ' and \""), "'both \\' and \"'");
        assert_eq!(py_repr("a\\b"), "'a\\\\b'");
        assert_eq!(py_repr("\0\t\n\x1b\x7f"), "'\\x00\\t\\n\\x1b\\x7f'");
        assert_eq!(py_repr("é日😀"), "'é日😀'");
        assert_eq!(py_repr("\u{a0}\u{2028}\u{feff}"), "'\\xa0\\u2028\\ufeff'");
        assert_eq!(py_repr("..\\\\escape"), "'..\\\\\\\\escape'");
    }

    #[test]
    fn path_str_matches_pure_posix_path() {
        assert_eq!(py_path_str(Path::new("./a//b/./c/")), "a/b/c");
        assert_eq!(py_path_str(Path::new("/tmp/x")), "/tmp/x");
        assert_eq!(py_path_str(Path::new("")), ".");
        assert_eq!(py_path_str(Path::new("a/../b")), "a/../b");
    }

    #[test]
    fn title_matches_python() {
        assert_eq!(py_title("docker-content-digest"), "Docker-Content-Digest");
        assert_eq!(py_title("x-ratelimit-remaining"), "X-Ratelimit-Remaining");
        assert_eq!(py_title("ETAG"), "Etag");
        assert_eq!(py_title("x1a"), "X1A");
        assert_eq!(py_title("www-authenticate"), "Www-Authenticate");
    }

    #[test]
    fn text_mode_translates_newlines() {
        assert_eq!(text_mode(b"a\r\nb\rc\n"), "a\nb\nc\n");
        assert_eq!(text_mode(b"\xffok"), "\u{fffd}ok");
    }

    #[test]
    fn char_slices() {
        assert_eq!(tail_chars("héllo", 3), "llo");
        assert_eq!(tail_chars("hé", 5), "hé");
        assert_eq!(tail_chars("abc", 0), "");
        assert_eq!(head_chars("héllo", 2), "hé");
        assert_eq!(head_chars("ab", 5), "ab");
    }
}
