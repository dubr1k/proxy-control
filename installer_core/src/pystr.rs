//! Python `str` semantics the configuration, the digest and the CLI messages depend on:
//! `isspace`/`strip`/`split()`, `lower()`, `str(Path)`, `Path.with_suffix`, tuple `repr`, and the
//! texts of `OSError` and `UnicodeDecodeError` that reach a `BLOCKED:` line.
//!
//! Golden vectors: `tests/fixtures/host-golden/vectors/str-*.json` (recorded from Python 3.12).

use std::io;
use std::path::{Path, PathBuf};

pub use pc_host::pytext::py_repr;

/// `str.isspace()` for one character (Python 3.12): the Unicode whitespace Rust knows plus the
/// four ASCII information separators `\x1c`-`\x1f`, which Python counts and Rust does not.
pub fn is_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n'
            | '\u{b}'
            | '\u{c}'
            | '\r'
            | '\u{1c}'..='\u{1f}'
            | ' '
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

/// `str.strip()` (no argument).
pub fn strip(text: &str) -> &str {
    text.trim_matches(is_space)
}

/// `str.split()` (no argument): runs of whitespace separate, no empty items.
pub fn split_whitespace(text: &str) -> Vec<&str> {
    text.split(is_space).filter(|part| !part.is_empty()).collect()
}

/// `str.lower()`: full Unicode lowercasing (final sigma included), as Rust's `to_lowercase`.
pub fn lower(text: &str) -> String {
    text.to_lowercase()
}

/// `len(text)`: code points.
pub fn char_len(text: &str) -> usize {
    text.chars().count()
}

/// The non-empty test of the planner (`isinstance(v, str) and bool(v.strip())`).
pub fn nonempty(text: &str) -> bool {
    !strip(text).is_empty()
}

/// Python's `\w` in a `str` pattern: letters, digits and `_`. Rust's alphanumeric property is
/// used for non-ASCII characters (it differs from Python only on rare marks and letter numbers).
pub fn is_word_char(c: char) -> bool {
    c == '_' || c.is_alphanumeric()
}

/// `repr(tuple_of_str)`: `('a',)`, `('a', 'b')`, `()`.
pub fn tuple_repr(items: &[String]) -> String {
    let parts: Vec<String> = items.iter().map(|item| py_repr(item)).collect();
    match parts.len() {
        1 => format!("({},)", parts[0]),
        _ => format!("({})", parts.join(", ")),
    }
}

/// `str(PurePosixPath(text))`: empty and `.` components dropped, repeated slashes collapsed,
/// exactly two leading slashes kept (POSIX), `.` for an empty relative path.
pub fn py_path_str(text: &str) -> String {
    let prefix = if text.starts_with("//") && !text.starts_with("///") {
        "//"
    } else if text.starts_with('/') {
        "/"
    } else {
        ""
    };
    let parts: Vec<&str> = text.split('/').filter(|part| !part.is_empty() && *part != ".").collect();
    let joined = format!("{prefix}{}", parts.join("/"));
    if joined.is_empty() {
        ".".into()
    } else {
        joined
    }
}

/// `Path(path).with_suffix(suffix)` (Python 3.12): the last suffix of the name is replaced, a
/// name without one gets it appended; a leading dot does not start a suffix.
pub fn with_suffix(path: &Path, suffix: &str) -> Result<PathBuf, String> {
    let text = path.to_string_lossy();
    let normalized = py_path_str(&text);
    let (parent, name) = match normalized.rfind('/') {
        Some(index) => (&normalized[..=index], &normalized[index + 1..]),
        None => ("", normalized.as_str()),
    };
    if name.is_empty() || name == "." || name == ".." {
        return Err(format!("PosixPath({}) has an empty name", py_repr(&normalized)));
    }
    let stem = match name.rfind('.') {
        Some(index) if index > 0 && index < name.len() - 1 => &name[..index],
        _ => name,
    };
    Ok(PathBuf::from(format!("{parent}{stem}{suffix}")))
}

/// `str(OSError)` for a failed call on `filename`: `[Errno 2] No such file or directory: 'x'`.
pub fn os_error_message(err: &io::Error, filename: &str) -> String {
    match err.raw_os_error() {
        Some(code) => format!("[Errno {code}] {}: {}", strerror(code), py_repr(filename)),
        None => err.to_string(),
    }
}

/// `os.strerror(code)` (glibc's text, which Rust's `io::Error` shows before ` (os error N)`).
pub fn strerror(code: i32) -> String {
    let text = io::Error::from_raw_os_error(code).to_string();
    match text.rfind(" (os error ") {
        Some(index) => text[..index].to_string(),
        None => text,
    }
}

/// `bytes.decode("utf-8")` with Python's `UnicodeDecodeError` text on failure.
pub fn decode_utf8(data: &[u8]) -> Result<String, String> {
    match std::str::from_utf8(data) {
        Ok(text) => Ok(text.to_string()),
        Err(err) => {
            let start = err.valid_up_to();
            let (end, reason) = match err.error_len() {
                None => (data.len(), "unexpected end of data"),
                Some(1) if !is_lead_byte(data[start]) => (start + 1, "invalid start byte"),
                Some(length) => (start + length, "invalid continuation byte"),
            };
            Err(if end - start == 1 {
                format!("'utf-8' codec can't decode byte 0x{:02x} in position {start}: {reason}", data[start])
            } else {
                format!("'utf-8' codec can't decode bytes in position {start}-{}: {reason}", end - 1)
            })
        }
    }
}

fn is_lead_byte(byte: u8) -> bool {
    matches!(byte, 0x00..=0x7f | 0xc2..=0xf4)
}

/// `Path(path).read_text(encoding="utf-8")`: strict UTF-8 and universal newlines (`\r\n` and
/// `\r` become `\n`). Errors carry Python's `OSError`/`UnicodeDecodeError` text.
pub fn read_text(path: &Path) -> Result<String, String> {
    let shown = py_path_str(&path.to_string_lossy());
    let data = std::fs::read(path).map_err(|err| os_error_message(&err, &shown))?;
    let text = decode_utf8(&data)?;
    Ok(universal_newlines(&text))
}

/// Text-mode newline translation.
pub fn universal_newlines(text: &str) -> String {
    if text.contains('\r') {
        text.replace("\r\n", "\n").replace('\r', "\n")
    } else {
        text.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_knows_the_information_separators() {
        assert_eq!(strip("\u{1c}a\u{1f}"), "a");
        assert_eq!(strip("\u{200b}a"), "\u{200b}a");
        assert_eq!(split_whitespace(" a \u{85}b\u{3000}"), vec!["a", "b"]);
    }

    #[test]
    fn paths_print_like_pure_posix_path() {
        assert_eq!(py_path_str(""), ".");
        assert_eq!(py_path_str("./a//b/"), "a/b");
        assert_eq!(py_path_str("//x/./y"), "//x/y");
        assert_eq!(py_path_str("///x"), "/x");
        assert_eq!(py_path_str("/"), "/");
    }

    #[test]
    fn with_suffix_matches_python() {
        let check = |input: &str| with_suffix(Path::new(input), ".credentials").map(|p| p.display().to_string());
        assert_eq!(check("/etc/pc/install.toml").unwrap(), "/etc/pc/install.credentials");
        assert_eq!(check("proxy-control.toml").unwrap(), "proxy-control.credentials");
        assert_eq!(check("a.b.toml").unwrap(), "a.b.credentials");
        assert_eq!(check(".hidden").unwrap(), ".hidden.credentials");
        assert_eq!(check("a.").unwrap(), "a..credentials");
        assert_eq!(check("noext").unwrap(), "noext.credentials");
        assert_eq!(check("/").unwrap_err(), "PosixPath('/') has an empty name");
    }

    #[test]
    fn decode_errors_read_like_python() {
        assert_eq!(
            decode_utf8(b"ok\xff").unwrap_err(),
            "'utf-8' codec can't decode byte 0xff in position 2: invalid start byte"
        );
        assert_eq!(
            decode_utf8(b"\xe2\x28\xa1").unwrap_err(),
            "'utf-8' codec can't decode byte 0xe2 in position 0: invalid continuation byte"
        );
        assert_eq!(
            decode_utf8(b"a\xf0\x9f\x98A").unwrap_err(),
            "'utf-8' codec can't decode bytes in position 1-3: invalid continuation byte"
        );
        assert_eq!(
            decode_utf8(b"a\xf0\x9f").unwrap_err(),
            "'utf-8' codec can't decode bytes in position 1-2: unexpected end of data"
        );
    }

    #[test]
    fn os_errors_read_like_python() {
        let err = io::Error::from_raw_os_error(2);
        assert_eq!(os_error_message(&err, "/x/y.toml"), "[Errno 2] No such file or directory: '/x/y.toml'");
    }

    #[test]
    fn tuple_repr_matches_python() {
        assert_eq!(tuple_repr(&["domains".into()]), "('domains',)");
        assert_eq!(tuple_repr(&["a".into(), "b".into()]), "('a', 'b')");
    }
}
