//! The server's log line, as Python's `%(asctime)s %(name)s %(levelname)s %(message)s` printed
//! it: `2026-10-25 12:00:00,123 proxy-control-mcp INFO message`, in UTC, on stderr.
//! (`pc_common::logger` writes the managers' format, which has no logger name.)

use std::io::Write;
use std::time::SystemTime;

struct Logger;

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Info
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
        let line = format!(
            "{} {} {} {}\n",
            pc_common::logger::timestamp(SystemTime::now()),
            record.target(),
            level,
            record.args()
        );
        let _ = std::io::stderr().lock().write_all(line.as_bytes());
    }

    fn flush(&self) {}
}

pub fn init_logger() {
    if log::set_logger(&Logger).is_ok() {
        log::set_max_level(log::LevelFilter::Info);
    }
}
