//! The managers' log line, as Python's `%(asctime)s %(levelname)s %(message)s` printed it:
//! `2026-10-25 12:00:00,123 INFO message`, in UTC, on stderr.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

struct Logger {
    level: log::LevelFilter,
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let level = match record.level() {
            log::Level::Error => "ERROR",
            log::Level::Warn => "WARNING",
            log::Level::Info => "INFO",
            log::Level::Debug | log::Level::Trace => "DEBUG",
        };
        let line = format!("{} {} {}\n", timestamp(SystemTime::now()), level, record.args());
        let _ = std::io::stderr().lock().write_all(line.as_bytes());
    }

    fn flush(&self) {}
}

/// Installs the logger once; later calls are no-ops.
pub fn init(level: log::LevelFilter) {
    if log::set_boxed_logger(Box::new(Logger { level })).is_ok() {
        log::set_max_level(level);
    }
}

pub fn timestamp(now: SystemTime) -> String {
    let since = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since.as_secs() as i64;
    let (year, month, day) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02},{:03}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        since.subsec_millis()
    )
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's algorithm).
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn formats_like_python_asctime() {
        let at = UNIX_EPOCH + Duration::from_millis(1_793_000_000_123);
        assert_eq!(timestamp(at), "2026-10-26 07:33:20,123");
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
    }
}
