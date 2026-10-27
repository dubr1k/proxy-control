//! Host primitives the Python manager took from its standard library: private state files,
//! the HMAC of the journal, random credentials, ISO timestamps.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::pyjson;

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// `hashlib.sha256(_canonical(value)).hexdigest()`.
pub fn hash(value: &Value) -> String {
    sha256_hex(pyjson::canonical(value).as_bytes())
}

pub fn is_hex64(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `hmac.new(key, message, hashlib.sha256).hexdigest()`.
pub fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let pad = |byte: u8| block.iter().map(|b| b ^ byte).collect::<Vec<u8>>();
    let inner = Sha256::new().chain_update(pad(0x36)).chain_update(message).finalize();
    hex(&Sha256::new().chain_update(pad(0x5c)).chain_update(inner).finalize())
}

pub fn random_bytes(count: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; count];
    getrandom::fill(&mut bytes).map_err(|err| Error::internal(format!("no randomness: {err}")))?;
    Ok(bytes)
}

/// `secrets.token_urlsafe(24)`: 32 URL-safe characters.
pub fn token_urlsafe(count: usize) -> Result<String> {
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes(count)?))
}

/// `datetime.now(UTC).isoformat()`: `2026-10-25T12:00:00.123456+00:00`, the fraction left out
/// when it is zero.
pub fn now_isoformat() -> String {
    isoformat(SystemTime::now())
}

pub fn isoformat(at: SystemTime) -> String {
    let since = at.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since.as_secs() as i64;
    let (year, month, day) = pc_common::logger::civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    let micros = since.subsec_micros();
    let fraction = if micros == 0 { String::new() } else { format!(".{micros:06}") };
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}{fraction}+00:00", rem / 3600, rem % 3600 / 60, rem % 60)
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        _ => 28,
    }
}

fn number(text: &str) -> Option<i64> {
    (!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())).then(|| text.parse().ok()).flatten()
}

/// `HH[:MM[:SS[.ffffff]]]` or the basic `HH[MM[SS[.ffffff]]]` as seconds (fraction truncated).
fn time_seconds(text: &str) -> Option<f64> {
    let (clock, fraction) = match text.find(['.', ',']) {
        Some(at) => (&text[..at], Some(&text[at + 1..])),
        None => (text, None),
    };
    let fields: Vec<&str> = if clock.contains(':') {
        clock.split(':').collect()
    } else {
        (0..clock.len()).step_by(2).map(|i| clock.get(i..i + 2).unwrap_or("")).collect()
    };
    if fields.is_empty() || fields.len() > 3 || fields.iter().any(|f| f.len() != 2) {
        return None;
    }
    let values: Vec<i64> = fields.iter().map(|f| number(f)).collect::<Option<_>>()?;
    let (h, m, s) = (values[0], *values.get(1).unwrap_or(&0), *values.get(2).unwrap_or(&0));
    if h > 23 || m > 59 || s > 59 {
        return None;
    }
    let mut seconds = (h * 3600 + m * 60 + s) as f64;
    if let Some(fraction) = fraction {
        if fields.len() != 3 || fraction.is_empty() || !fraction.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let micros: String = fraction.chars().take(6).collect();
        seconds += micros.parse::<f64>().ok()? / 10f64.powi(micros.len() as i32);
    }
    Some(seconds)
}

/// `datetime.fromisoformat(text).timestamp()` for the forms an ISO writer produces: a date
/// (`YYYY-MM-DD` or `YYYYMMDD`), optionally a separator and a time, optionally `Z` or an
/// offset. A naive time is taken as UTC (the manager's container has no local zone).
pub fn fromisoformat_timestamp(text: &str) -> Option<f64> {
    let (date, rest) = if text.len() >= 10 && text.as_bytes().get(4) == Some(&b'-') {
        (text.get(..10)?, text.get(10..)?)
    } else {
        (text.get(..8)?, text.get(8..)?)
    };
    let (year, month, day) = if date.len() == 10 {
        let parts: Vec<&str> = date.split('-').collect();
        if parts.len() != 3 || parts[0].len() != 4 || parts[1].len() != 2 || parts[2].len() != 2 {
            return None;
        }
        (number(parts[0])?, number(parts[1])?, number(parts[2])?)
    } else {
        (number(&date[..4])?, number(&date[4..6])?, number(&date[6..8])?)
    };
    let (month, day) = (u32::try_from(month).ok()?, u32::try_from(day).ok()?);
    if !(1..=9999).contains(&year) || !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return None;
    }
    let mut seconds = 0.0;
    let mut offset = 0.0;
    if !rest.is_empty() {
        let mut chars = rest.chars();
        chars.next()?; // any single separator character
        let time = chars.as_str();
        let (clock, zone) = match time.find(['+', '-', 'Z']) {
            Some(at) => (&time[..at], Some(&time[at..])),
            None => (time, None),
        };
        seconds = time_seconds(clock)?;
        if let Some(zone) = zone {
            offset = match zone {
                "Z" => 0.0,
                _ => {
                    let sign = if zone.starts_with('-') { -1.0 } else { 1.0 };
                    sign * time_seconds(&zone[1..])?
                }
            };
        }
    }
    Some(days_from_civil(year, month, day) as f64 * 86_400.0 + seconds - offset)
}

pub fn now_timestamp() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// `int(text, base)` of Python for the octal socket mode: optional sign, `0o` prefix, `_`
/// between digits.
pub fn parse_int(text: &str, base: u32) -> Option<i64> {
    let text = pc_common::pytext::strip(text);
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let digits = if base == 8 {
        digits.strip_prefix("0o").or_else(|| digits.strip_prefix("0O")).unwrap_or(digits)
    } else {
        digits
    };
    if digits.is_empty() || digits.starts_with('_') || digits.ends_with('_') || digits.contains("__") {
        return None;
    }
    let value = i64::from_str_radix(&digits.replace('_', ""), base).ok()?;
    Some(if negative { -value } else { value })
}

/// `Path.mkdir(parents=True, exist_ok=True, mode=mode)`: parents with the default mode, the
/// directory itself with `mode` (under the umask) when it is created.
pub fn mkdir(path: &Path, mode: u32) -> io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }
    match fs::DirBuilder::new().mode(mode).create(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists && path.is_dir() => Ok(()),
        Err(err) => Err(err),
    }
}

/// `_atomic(path, value)`: the canonical text plus a newline (or the bytes as they are),
/// written to a 0600 sibling, fsynced and renamed over the file.
pub fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        mkdir(parent, 0o700)?;
    }
    pc_common::fsutil::write_atomic(path, data, 0o600)
}

pub fn atomic_json(path: &Path, value: &Value) -> io::Result<()> {
    let mut data = pyjson::canonical(value).into_bytes();
    data.push(b'\n');
    atomic_write(path, &data)
}

pub fn fsync_dir(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

/// `os.path.lexists`.
pub fn lexists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// `_read_secure`: a regular 0600 file, not a symlink, the same inode when opened, at most
/// `max_size` bytes; anything else is `unsafe transaction recovery file`.
pub fn read_secure(path: &Path, max_size: usize) -> Result<Vec<u8>> {
    let unsafe_file = || Error::conflict("unsafe transaction recovery file");
    let before = fs::symlink_metadata(path).map_err(|_| unsafe_file())?;
    if !before.file_type().is_file() || before.permissions().mode() & 0o7777 != 0o600 {
        return Err(unsafe_file());
    }
    let mut file =
        OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path).map_err(|_| unsafe_file())?;
    let after = file.metadata().map_err(|_| unsafe_file())?;
    if (before.dev(), before.ino()) != (after.dev(), after.ino())
        || !after.file_type().is_file()
        || after.permissions().mode() & 0o7777 != 0o600
        || after.len() > max_size as u64
    {
        return Err(unsafe_file());
    }
    let mut data = Vec::new();
    file.by_ref().take(max_size as u64 + 1).read_to_end(&mut data).map_err(|_| unsafe_file())?;
    if data.len() > max_size {
        return Err(unsafe_file());
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn hmac_matches_the_rfc_4231_vector() {
        let key = [0x0bu8; 20];
        assert_eq!(
            hmac_sha256_hex(&key, b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn isoformat_round_trips_through_fromisoformat() {
        let at = UNIX_EPOCH + Duration::from_micros(1_793_000_000_123_456);
        let text = isoformat(at);
        assert_eq!(text, "2026-10-26T07:33:20.123456+00:00");
        assert_eq!(isoformat(UNIX_EPOCH + Duration::from_secs(1_793_000_000)), "2026-10-26T07:33:20+00:00");
        assert!((fromisoformat_timestamp(&text).unwrap() - 1_793_000_000.123456).abs() < 1e-5);
        assert_eq!(fromisoformat_timestamp("2000-01-01T00:00:00+00:00"), Some(946_684_800.0));
        assert_eq!(fromisoformat_timestamp("2000-01-01T03:00:00+03:00"), Some(946_684_800.0));
        assert_eq!(fromisoformat_timestamp("2000-01-01"), Some(946_684_800.0));
        assert_eq!(fromisoformat_timestamp("20000101T000000Z"), Some(946_684_800.0));
        for bad in ["", "yesterday", "2000-02-30T00:00:00", "2000-01-01T25:00:00", "2000-1-01"] {
            assert!(fromisoformat_timestamp(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn octal_modes_parse_like_python_int() {
        assert_eq!(parse_int("660", 8), Some(0o660));
        assert_eq!(parse_int("0o600", 8), Some(0o600));
        assert_eq!(parse_int("9", 8), None);
        assert_eq!(parse_int(" 1_0 ", 10), Some(10));
    }
}
