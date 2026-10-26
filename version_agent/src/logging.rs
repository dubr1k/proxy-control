//! The agent's log line: Python's `logging.basicConfig(level=INFO, format="%(name)s:
//! %(message)s")` on stderr (journald adds the time). The logger name is the record's target:
//! `version_agent`, `version_agent.metrics`.

use std::io::Write;

struct Logger;

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Info
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let _ = std::io::stderr().lock().write_all(line(record.target(), &record.args().to_string()).as_bytes());
        }
    }

    fn flush(&self) {}
}

/// `<name>: <message>\n`.
pub fn line(name: &str, message: &str) -> String {
    format!("{name}: {message}\n")
}

/// Installs the logger once; later calls are no-ops.
pub fn init() {
    if log::set_logger(&Logger).is_ok() {
        log::set_max_level(log::LevelFilter::Info);
    }
}

/// The bare `print(..., file=sys.stderr)` lines of the agent: `version-agent: <message>`.
pub fn print(message: &str) {
    let _ = std::io::stderr().lock().write_all(format!("version-agent: {message}\n").as_bytes());
}

#[cfg(test)]
mod tests {
    #[test]
    fn lines_carry_the_logger_name() {
        assert_eq!(
            super::line("version_agent.metrics", "kernel counters unavailable: x"),
            "version_agent.metrics: kernel counters unavailable: x\n"
        );
    }
}
