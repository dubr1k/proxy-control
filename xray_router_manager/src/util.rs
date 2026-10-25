//! Python semantics the manager's behaviour rests on — whitespace, digits, `int()`, line
//! splitting, truthiness — plus the host primitives of the Python version: `mkstemp`-style atomic
//! files, UTC timestamps, randomness (`secrets`, `uuid4`), and its log line.
//!
//! Candidates for `pc_common`: `atomic_write` (unique temporary names: two threads may write the
//! same file), `py_strip`/`py_int`, `Logger`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// `str.isspace()`: what `strip()`, `split()` and the regex `\s` treat as whitespace.
pub fn py_isspace(c: char) -> bool {
    matches!(c as u32, 0x09..=0x0d | 0x1c..=0x20 | 0x85 | 0xa0 | 0x1680 | 0x2000..=0x200a | 0x2028 | 0x2029 | 0x202f | 0x205f | 0x3000)
}

/// `str.strip()` without arguments.
pub fn py_strip(text: &str) -> &str {
    text.trim_matches(py_isspace)
}

/// The zero of every run of Unicode decimal digits (`str.isdecimal()`, the regex `\d`), Unicode
/// 15.1 as in Python 3.13.
const DECIMAL_ZEROS: [u32; 68] = [
    0x30, 0x660, 0x6f0, 0x7c0, 0x966, 0x9e6, 0xa66, 0xae6, 0xb66, 0xbe6, 0xc66, 0xce6, 0xd66, 0xde6, 0xe50, 0xed0,
    0xf20, 0x1040, 0x1090, 0x17e0, 0x1810, 0x1946, 0x19d0, 0x1a80, 0x1a90, 0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620,
    0xa8d0, 0xa900, 0xa9d0, 0xa9f0, 0xaa50, 0xabf0, 0xff10, 0x104a0, 0x10d30, 0x11066, 0x110f0, 0x11136, 0x111d0,
    0x112f0, 0x11450, 0x114d0, 0x11650, 0x116c0, 0x11730, 0x118e0, 0x11950, 0x11c50, 0x11d50, 0x11da0, 0x11f50,
    0x16a60, 0x16ac0, 0x16b50, 0x1d7ce, 0x1d7d8, 0x1d7e2, 0x1d7ec, 0x1d7f6, 0x1e140, 0x1e2f0, 0x1e4f0, 0x1e950,
    0x1fbf0,
];

/// The value of a Unicode decimal digit, as `int()` reads it.
pub fn py_decimal(c: char) -> Option<u32> {
    let code = c as u32;
    DECIMAL_ZEROS.iter().find(|zero| code >= **zero && code < **zero + 10).map(|zero| code - zero)
}

/// `int(text, base)` for base 8 or 10: surrounding whitespace, a sign, single underscores between
/// digits, Unicode decimal digits, and `0o` in base 8. `None` where Python raises (or the value
/// does not fit 128 bits).
pub fn py_int(text: &str, base: u32) -> Option<i128> {
    let text = py_strip(text);
    let (negative, digits) = match text.chars().next() {
        Some('-') => (true, &text[1..]),
        Some('+') => (false, &text[1..]),
        _ => (false, text),
    };
    let digits = if base == 8 {
        digits
            .strip_prefix("0o")
            .or_else(|| digits.strip_prefix("0O"))
            .map(|rest| rest.strip_prefix('_').unwrap_or(rest))
            .unwrap_or(digits)
    } else {
        digits
    };
    if digits.is_empty() || digits.starts_with('_') || digits.ends_with('_') || digits.contains("__") {
        return None;
    }
    let mut value: i128 = 0;
    for c in digits.chars() {
        if c == '_' {
            continue;
        }
        let digit = py_decimal(c).filter(|d| *d < base)?;
        value = value.checked_mul(base as i128)?.checked_add(digit as i128)?;
    }
    Some(if negative { -value } else { value })
}

/// `text[:n]` in characters.
pub fn first_chars(text: &str, n: usize) -> &str {
    match text.char_indices().nth(n) {
        Some((index, _)) => &text[..index],
        None => text,
    }
}

/// `text[-n:]` in characters.
pub fn last_chars(text: &str, n: usize) -> &str {
    let count = text.chars().count();
    if count <= n {
        return text;
    }
    let (index, _) = text.char_indices().nth(count - n).expect("within bounds");
    &text[index..]
}

/// `str.splitlines()`.
pub fn py_splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((index, c)) = chars.next() {
        let boundary = matches!(
            c,
            '\n' | '\r' | '\u{0b}' | '\u{0c}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}' | '\u{2028}' | '\u{2029}'
        );
        if !boundary {
            continue;
        }
        lines.push(&text[start..index]);
        let mut end = index + c.len_utf8();
        if c == '\r' {
            if let Some((next, '\n')) = chars.peek().copied() {
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

/// Python truthiness of a JSON value.
pub fn py_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|n| n != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// `value == n` with Python's numeric equality (`True == 1`, `2.0 == 2`).
pub fn py_eq_int(value: Option<&Value>, n: i64) -> bool {
    match value {
        Some(Value::Bool(flag)) => i64::from(*flag) == n,
        Some(Value::Number(number)) => match number.as_i64() {
            Some(i) => i == n,
            None => number.as_f64() == Some(n as f64),
        },
        _ => false,
    }
}

/// A JSON integer (not a bool, not a float), as `isinstance(v, int) and not isinstance(v, bool)`.
pub fn json_int(value: &Value) -> Option<i128> {
    match value {
        Value::Number(number) if !number.is_f64() => {
            number.as_i64().map(i128::from).or_else(|| number.as_u64().map(i128::from))
        }
        _ => None,
    }
}

/// `str(exc)` of an `OSError`: `[Errno N] message` where the OS gave a number.
pub fn py_oserror(err: &io::Error) -> String {
    match err.raw_os_error() {
        Some(code) => {
            let text = io::Error::from_raw_os_error(code).to_string();
            let text = text.strip_suffix(&format!(" (os error {code})")).unwrap_or(&text).to_string();
            format!("[Errno {code}] {text}")
        }
        None => err.to_string(),
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; n];
    getrandom::fill(&mut bytes).expect("the OS random source is available");
    bytes
}

/// `secrets.token_urlsafe(n)`.
pub fn token_urlsafe(n: usize) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes(n))
}

/// `secrets.token_hex(n)`.
pub fn token_hex(n: usize) -> String {
    hex(&random_bytes(n))
}

/// `str(uuid.uuid4())`.
pub fn uuid4() -> String {
    let mut b = random_bytes(16);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex(&b);
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

/// Seconds since the epoch, as `time.time()`.
pub fn unix_now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// `time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))`.
pub fn iso_utc(seconds: f64) -> String {
    let secs = seconds.floor() as i64;
    let (year, month, day) = pc_common::logger::civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

pub fn now_iso() -> String {
    iso_utc(unix_now())
}

const TEMP_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789_";

fn temp_name(prefix: &str, suffix: &str) -> String {
    let random: String = random_bytes(8).iter().map(|b| TEMP_CHARS[*b as usize % TEMP_CHARS.len()] as char).collect();
    format!("{prefix}{random}{suffix}")
}

/// `tempfile.mkstemp(prefix=…, suffix=…, dir=…)`: a new file only this call created, mode 0600.
pub fn mkstemp(dir: &Path, prefix: &str, suffix: &str) -> io::Result<(File, PathBuf)> {
    loop {
        let path = dir.join(temp_name(prefix, suffix));
        match OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path) {
            Ok(file) => return Ok((file, path)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
}

/// `tempfile.mkdtemp(prefix=…, dir=…)`: a new directory, mode 0700.
pub fn mkdtemp(dir: &Path, prefix: &str) -> io::Result<PathBuf> {
    loop {
        let path = dir.join(temp_name(prefix, ""));
        match fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return Ok(path),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
}

pub fn fsync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

/// Creates `path` (mode 0700 for the last component, like `mkdir(parents=True, mode=0o700)`).
pub fn make_dirs(path: &Path) -> io::Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists && path.is_dir() => Ok(()),
        other => other,
    }
}

/// The state files' write: a unique sibling (`.<name>.XXXXXXXX`) with the exact mode, fsync,
/// rename, fsync of the directory; the sibling goes away on any failure.
pub fn atomic_write(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    make_dirs(parent)?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    replace_with(parent, &format!(".{name}."), path, data, mode, true)
}

/// The geodata store's write (`<name>.XXXXXXXX` beside the file, no directory creation); a
/// directory that cannot be opened for its fsync is not an error.
pub fn atomic_write_geodata(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    replace_with(parent, &format!("{name}."), path, data, mode, false)
}

fn replace_with(parent: &Path, prefix: &str, path: &Path, data: &[u8], mode: u32, strict_dir: bool) -> io::Result<()> {
    let (mut file, temporary) = mkstemp(parent, prefix, "")?;
    let written = (|| {
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(data)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        match fsync_directory(parent) {
            Err(err) if strict_dir => Err(err),
            _ => Ok(()),
        }
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written
}

/// `Path.unlink(missing_ok=True)`.
pub fn unlink_missing_ok(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// The Python manager's log line: `logging.basicConfig(level=WARNING, format="%(name)s: %(message)s")`.
struct Logger;

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Warn
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let line = format!("xray_router_manager: {}\n", record.args());
            let _ = io::stderr().lock().write_all(line.as_bytes());
        }
    }

    fn flush(&self) {}
}

pub fn init_logger() {
    if log::set_boxed_logger(Box::new(Logger)).is_ok() {
        log::set_max_level(log::LevelFilter::Warn);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_strings_and_numbers() {
        assert_eq!(py_strip("\u{1c} a b\u{3000}\n"), "a b");
        assert_eq!(py_int(" 080 ", 10), Some(80));
        assert_eq!(py_int("\u{0668}\u{0660}", 10), Some(80));
        assert_eq!(py_int("1_000", 10), Some(1000));
        assert_eq!(py_int("1__0", 10), None);
        assert_eq!(py_int("660", 8), Some(0o660));
        assert_eq!(py_int("0o_640", 8), Some(0o640));
        assert_eq!(py_int("9", 8), None);
        assert_eq!(py_int("+12", 10), Some(12));
        assert_eq!(py_int("\u{00b2}", 10), None);
        assert_eq!(py_splitlines("a\r\nb\rc\u{2028}d\n"), ["a", "b", "c", "d"]);
        assert_eq!(py_splitlines("a\n\nb"), ["a", "", "b"]);
        assert_eq!(last_chars("žluť", 2), "uť");
        assert_eq!(first_chars("žluť", 2), "žl");
        assert_eq!(iso_utc(1_790_000_000.9), "2026-09-21T14:13:20Z");
    }

    #[test]
    fn uuid_and_tokens_have_python_shapes() {
        let id = uuid4();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
        assert!(matches!(&id[19..20], "8" | "9" | "a" | "b"));
        assert_eq!(token_urlsafe(32).len(), 43);
        assert_eq!(token_hex(4).len(), 8);
    }

    #[test]
    fn atomic_writes_keep_the_mode_and_leave_no_temporaries() {
        let dir = std::env::temp_dir().join(format!("xr-util-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("nested/state.json");
        atomic_write(&path, b"one", 0o600).unwrap();
        atomic_write(&path, b"two", 0o640).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o640);
        assert_eq!(fs::metadata(dir.join("nested")).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::read_dir(dir.join("nested")).unwrap().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }
}
