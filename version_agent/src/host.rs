//! `GET /v1/host` (`version_agent/host.py`): CPU utilisation, memory, swap and the root
//! filesystem, read-only. The panel container cannot see the host, so the agent reads for it.
//! Every section degrades to `null` on its own.

use std::path::PathBuf;
use std::time::Duration;

use serde_json::{json, Value};

use crate::hostmetrics::{cpu_count, statvfs, StatVfsFn};
use crate::py;

/// Utilisation is a rate: two `/proc/stat` samples this far apart, inside the request.
pub const SAMPLE: Duration = Duration::from_millis(150);

/// Utilisation between two `(total, idle)` samples. A counter that did not advance says
/// nothing; reporting 0% would be a lie.
fn used_percent(first: (i64, i64), second: (i64, i64)) -> Value {
    let (total, idle) = (second.0 - first.0, second.1 - first.1);
    if total > 0 {
        py::round_json((100.0 * (total - idle) as f64 / total as f64).clamp(0.0, 100.0), 1)
    } else {
        Value::Null
    }
}

/// Where the host telemetry is read from.
pub struct HostReader {
    pub proc: PathBuf,
    pub root: String,
    pub sample: Duration,
    pub statvfs: Box<StatVfsFn>,
    pub cores: Option<i64>,
}

impl Default for HostReader {
    fn default() -> Self {
        HostReader {
            proc: "/proc".into(),
            root: "/".into(),
            sample: SAMPLE,
            statvfs: Box::new(statvfs),
            cores: cpu_count(),
        }
    }
}

impl HostReader {
    fn read(&self, name: &str) -> Option<String> {
        std::fs::read(self.proc.join(name)).ok().and_then(|data| String::from_utf8(data).ok())
    }

    /// Total and idle (+iowait) jiffies of the aggregate `cpu` line.
    fn cpu_times(&self) -> Option<(i64, i64)> {
        let text = self.read("stat")?;
        let fields = pc_common::pytext::split(text.split('\n').next().unwrap_or(""));
        if fields.len() < 6 || fields[0] != "cpu" {
            return None;
        }
        let values = fields[1..].iter().map(|v| v.parse::<i64>()).collect::<Result<Vec<_>, _>>().ok()?;
        Some((values.iter().sum(), values[3] + values[4]))
    }

    pub fn cpu(&self) -> Value {
        let Some(first) = self.cpu_times() else { return Value::Null };
        std::thread::sleep(self.sample);
        let Some(second) = self.cpu_times() else { return Value::Null };
        json!({"cores": self.cores, "load_average": self.load_average(), "used_percent": used_percent(first, second)})
    }

    pub fn load_average(&self) -> Value {
        let Some(text) = self.read("loadavg") else { return Value::Null };
        pc_common::pytext::split(&text)
            .into_iter()
            .take(3)
            .map(|v| v.parse::<f64>().ok().filter(|f| f.is_finite()).map(|f| py::round_json(f, 2)))
            .collect::<Option<Vec<Value>>>()
            .map(Value::Array)
            .unwrap_or(Value::Null)
    }

    /// `/proc/meminfo` in bytes; `None` when unreadable.
    fn meminfo(&self) -> Option<Vec<(String, i64)>> {
        let text = self.read("meminfo")?;
        let mut values: Vec<(String, i64)> = Vec::new();
        for line in pc_common::pytext::splitlines(&text) {
            let (key, rest) = line.split_once(':').unwrap_or((line, ""));
            if let Some(number) = pc_common::pytext::split(rest)
                .first()
                .filter(|f| pc_common::pytext::is_ascii_digits(f))
                .and_then(|f| f.parse::<i64>().ok())
            {
                values.retain(|(known, _)| known != key);
                values.push((key.to_string(), number * 1024));
            }
        }
        Some(values)
    }

    pub fn memory(&self) -> Value {
        let Some(values) = self.meminfo() else { return Value::Null };
        let get = |key: &str| values.iter().find(|(k, _)| k == key).map(|(_, v)| *v);
        // MemAvailable, not MemFree: reclaimable cache is not memory pressure.
        let (Some(total), Some(available)) = (get("MemTotal").filter(|t| *t != 0), get("MemAvailable")) else {
            return Value::Null;
        };
        let available = available.min(total);
        json!({"total_bytes": total, "available_bytes": available, "used_bytes": total - available,
               "used_percent": py::round_json(100.0 * (total - available) as f64 / total as f64, 1)})
    }

    /// No swap is a fact about the server, not a missing reading: zero total, no percentage.
    pub fn swap(&self) -> Value {
        let Some(values) = self.meminfo() else { return Value::Null };
        let get = |key: &str| values.iter().find(|(k, _)| k == key).map(|(_, v)| *v);
        let (Some(total), Some(free)) = (get("SwapTotal"), get("SwapFree")) else { return Value::Null };
        if total == 0 {
            return json!({"total_bytes": 0, "available_bytes": 0, "used_bytes": 0});
        }
        let free = free.min(total);
        json!({"total_bytes": total, "available_bytes": free, "used_bytes": total - free,
               "used_percent": py::round_json(100.0 * (total - free) as f64 / total as f64, 1)})
    }

    /// `f_bavail` is what an operator can still write; `f_bfree` would promise reserved space.
    pub fn disk(&self, path: &str) -> Value {
        let Ok(stat) = (self.statvfs)(path) else { return Value::Null };
        let total = i128::from(stat.blocks) * i128::from(stat.frsize);
        if total <= 0 {
            return Value::Null;
        }
        let available = i128::from(stat.bavail) * i128::from(stat.frsize);
        let used = total - i128::from(stat.bfree) * i128::from(stat.frsize);
        json!({"total_bytes": total as i64, "available_bytes": available as i64, "used_bytes": used as i64,
               "used_percent": py::round_json(100.0 * used as f64 / total as f64, 1)})
    }

    /// `host_metrics()`.
    pub fn host_metrics(&self) -> Value {
        json!({"cpu": self.cpu(), "memory": self.memory(), "swap": self.swap(), "disk": self.disk(&self.root)})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    const STAT: &str = "cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 1 2 3 4\nintr 9\n";
    const STAT_LATER: &str = "cpu  200 0 200 1300 100 0 0 0 0 0\ncpu0 1 2 3 4\nintr 9\n";
    const MEMINFO: &str =
        "MemTotal:       4008032 kB\nMemFree:         128000 kB\nMemAvailable:   2909568 kB\nBuffers: 100 kB\n";

    fn reader(dir: &TempDir) -> HostReader {
        HostReader { proc: dir.path().to_path_buf(), sample: Duration::ZERO, ..HostReader::default() }
    }

    /// `/proc/stat` that changes between the two reads of one request.
    fn cpu_with(dir: &TempDir, first: &str, second: &str) -> Value {
        dir.write("stat", first);
        let reader = reader(dir);
        let before = reader.cpu_times();
        dir.write("stat", second);
        let after = reader.cpu_times();
        let (Some(before), Some(after)) = (before, after) else { return Value::Null };
        used_percent(before, after)
    }

    #[test]
    fn cpu_utilisation_is_a_delta_between_two_samples() {
        let dir = TempDir::new("host-cpu");
        dir.write("loadavg", "0.50 0.40 0.30 1/200 5\n");
        // 200 busy jiffies against 800 elapsed: idle+iowait grew 600, total grew 800.
        assert_eq!(cpu_with(&dir, STAT, STAT_LATER), json!(25.0));
        assert_eq!(reader(&dir).load_average(), json!([0.5, 0.4, 0.3]));
        let cpu = reader(&dir).cpu();
        assert_eq!(cpu["load_average"], json!([0.5, 0.4, 0.3]));
        assert_eq!(cpu["cores"], json!(cpu_count()));
    }

    #[test]
    fn a_stalled_counter_reports_null_rather_than_a_confident_zero() {
        let dir = TempDir::new("host-stalled");
        dir.write("loadavg", "0.00 0.00 0.00 1/1 2\n");
        dir.write("stat", STAT);
        assert_eq!(reader(&dir).cpu()["used_percent"], Value::Null);
        assert_eq!(cpu_with(&dir, STAT, STAT), Value::Null);
    }

    #[test]
    fn memory_counts_reclaimable_cache_as_available() {
        let dir = TempDir::new("host-memory");
        dir.write("meminfo", MEMINFO);
        let memory = reader(&dir).memory();
        assert_eq!(memory["total_bytes"], json!(4008032_i64 * 1024));
        assert_eq!(memory["available_bytes"], json!(2909568_i64 * 1024));
        assert_eq!(memory["used_percent"], json!(27.4));
    }

    #[test]
    fn swap_is_reported_beside_memory_and_a_host_without_swap_says_so() {
        let dir = TempDir::new("host-swap");
        dir.write("meminfo", &format!("{MEMINFO}SwapTotal:  2097152 kB\nSwapFree:   1966080 kB\n"));
        assert_eq!(
            reader(&dir).swap(),
            json!({"total_bytes": 2097152_i64 * 1024, "available_bytes": 1966080_i64 * 1024, "used_bytes": 131072_i64 * 1024,
                   "used_percent": 6.2})
        );
        dir.write("meminfo", &format!("{MEMINFO}SwapTotal:  0 kB\nSwapFree:   0 kB\n"));
        assert_eq!(reader(&dir).swap(), json!({"total_bytes": 0, "available_bytes": 0, "used_bytes": 0}));
        dir.write("meminfo", MEMINFO);
        assert_eq!(reader(&dir).swap(), Value::Null);
    }

    #[test]
    fn missing_proc_files_degrade_each_section_independently() {
        let dir = TempDir::new("host-empty");
        let metrics = reader(&dir).host_metrics();
        assert_eq!((&metrics["cpu"], &metrics["memory"]), (&Value::Null, &Value::Null));
        // statvfs still works, so the disk row survives a blank /proc.
        assert!(metrics["disk"]["total_bytes"].as_i64().unwrap() > 0);
    }

    #[test]
    fn disk_reports_space_an_operator_can_actually_write() {
        let dir = TempDir::new("host-disk");
        let disk = reader(&dir).disk(dir.path().to_str().unwrap());
        assert!(disk["available_bytes"].as_i64().unwrap() <= disk["total_bytes"].as_i64().unwrap());
        let percent = disk["used_percent"].as_f64().unwrap();
        assert!((0.0..=100.0).contains(&percent));
    }

    #[test]
    fn real_proc_is_parsed_on_linux() {
        if !std::path::Path::new("/proc/stat").exists() {
            return;
        }
        let metrics = HostReader::default().host_metrics();
        assert!(metrics["memory"]["total_bytes"].as_i64().unwrap() > 0);
        let percent = metrics["cpu"]["used_percent"].as_f64().unwrap_or(0.0);
        assert!((0.0..=100.0).contains(&percent));
    }
}
