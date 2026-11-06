//! Strict source-timed process counter deltas, separate from completed-tunnel quotas.
use serde_json::Value;

pub const SEMANTICS: &str = "authenticated_connect_payload";
pub const INTERVAL: f64 = 2.0;
pub const TIMEOUT: f64 = 1.5;

#[derive(Debug, Clone)]
pub struct Sample {
    pub epoch: String,
    pub at_ms: u64,
    pub up: u64,
    pub down: u64,
    pub tunnels: u64,
}

impl Sample {
    fn parse(value: &Value) -> Result<Self, ()> {
        let epoch = value.get("process_epoch").and_then(Value::as_str).ok_or(())?;
        if value.get("schema").and_then(Value::as_u64) != Some(1)
            || value.get("semantics").and_then(Value::as_str) != Some(SEMANTICS)
            || epoch.is_empty()
            || epoch.len() > 128
        {
            return Err(());
        }
        let number = |name| value.get(name).and_then(Value::as_u64).ok_or(());
        Ok(Self {
            epoch: epoch.into(),
            at_ms: number("sampled_at_ms")?,
            up: number("upload_bytes")?,
            down: number("download_bytes")?,
            tunnels: number("active_tunnels")?,
        })
    }
}

#[derive(Debug, Default)]
pub struct LiveMeter {
    pub sample: Option<Sample>,
    rates: Option<(f64, f64)>,
    pending: Option<(f64, f64)>,
    received_at: Option<f64>,
    watermark: Option<(String, u64)>,
}

impl LiveMeter {
    pub fn update(&mut self, value: &Value, received_at: f64) -> Result<(), ()> {
        let sample = match Sample::parse(value) {
            Ok(sample) => sample,
            Err(()) => {
                self.unavailable();
                return Err(());
            }
        };
        // Duplicate/out-of-order cached samples do not refresh freshness or invent zero.
        if self.watermark.as_ref().is_some_and(|(epoch, at)| *epoch == sample.epoch && sample.at_ms <= *at) {
            return Err(());
        }
        let delta = self.sample.as_ref().filter(|s| s.epoch == sample.epoch).and_then(|s| {
            Some((sample.up.checked_sub(s.up)?, sample.down.checked_sub(s.down)?, sample.at_ms - s.at_ms))
        });
        self.rates = delta.map(|(up, down, ms)| (up as f64 * 1000.0 / ms as f64, down as f64 * 1000.0 / ms as f64));
        match delta {
            Some((up, down, _)) => {
                let pending = self.pending.get_or_insert((0.0, 0.0));
                pending.0 += up as f64;
                pending.1 += down as f64;
            }
            None => self.pending = None,
        }
        self.watermark = Some((sample.epoch.clone(), sample.at_ms));
        self.sample = Some(sample);
        self.received_at = Some(received_at);
        Ok(())
    }
    pub fn unavailable(&mut self) {
        let watermark = self.watermark.take();
        *self = Self { watermark, ..Self::default() };
    }
    pub fn fresh(&self, now: f64) -> bool {
        self.received_at.is_some_and(|at| now - at <= INTERVAL * 3.0)
    }
    pub fn rates(&self) -> Option<(f64, f64)> {
        self.rates
    }
    pub fn take_delta(&mut self) -> Option<(f64, f64)> {
        self.pending.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    fn sample(epoch: &str, at: u64, up: u64, down: u64) -> Value {
        json!({"schema":1,"semantics":"authenticated_connect_payload","process_epoch":epoch,
            "sampled_at_ms":at,"upload_bytes":up,"download_bytes":down,"active_tunnels":3})
    }
    #[test]
    fn open_tunnel_rates_use_source_time_not_poll_latency() {
        let mut meter = LiveMeter::default();
        meter.update(&sample("one", 1000, 10, 20), 7.0).unwrap();
        assert_eq!(meter.rates(), None);
        meter.update(&sample("one", 3000, 110, 420), 15.0).unwrap();
        assert_eq!(meter.rates(), Some((50.0, 200.0)));
        assert_eq!(meter.take_delta(), Some((100.0, 400.0)));
        assert_eq!(meter.take_delta(), None);
        assert!(meter.fresh(19.0));
        assert!(!meter.fresh(22.0));
    }
    #[test]
    fn restart_regression_duplicate_and_failure_never_create_zero_or_spike() {
        let mut meter = LiveMeter::default();
        meter.update(&sample("one", 1000, 100, 200), 1.0).unwrap();
        meter.update(&sample("one", 3000, 120, 240), 3.0).unwrap();
        assert_eq!(meter.rates(), Some((10.0, 20.0)));
        assert!(meter.update(&sample("one", 3000, 120, 240), 5.0).is_err());
        assert_eq!(meter.rates(), Some((10.0, 20.0))); // no cached zero
        meter.update(&sample("two", 10, 5000, 9000), 6.0).unwrap();
        assert_eq!(meter.rates(), None);
        assert_eq!(meter.take_delta(), None);
        meter.update(&sample("two", 2010, 10, 10), 8.0).unwrap();
        assert_eq!(meter.rates(), None);
        meter.unavailable();
        assert!(!meter.fresh(8.0));
        meter.update(&sample("two", 4010, 5000, 8000), 9.0).unwrap();
        assert_eq!(meter.rates(), None);
    }
    #[test]
    fn expired_cached_sample_never_becomes_fresh_again_after_baseline_clear() {
        let mut meter = LiveMeter::default();
        let cached = sample("one", 1000, 10, 20);
        meter.update(&cached, 1.0).unwrap();
        assert!(!meter.fresh(8.0));
        meter.unavailable();
        assert!(meter.update(&cached, 8.0).is_err());
        assert!(!meter.fresh(8.0));
        meter.update(&sample("one", 3000, 100, 200), 9.0).unwrap();
        assert!(meter.fresh(9.0));
        assert_eq!(meter.rates(), None);
    }

    #[test]
    fn retains_integer_precision_and_rejects_unknown_semantics() {
        let mut meter = LiveMeter::default();
        let base = 1_u64 << 60;
        meter.update(&sample("one", 1000, base, base), 1.0).unwrap();
        meter.update(&sample("one", 2000, base + 1, base + 2), 2.0).unwrap();
        assert_eq!(meter.rates(), Some((1.0, 2.0)));
        let mut invalid = sample("one", 3000, base, base);
        invalid["semantics"] = json!("kernel");
        assert!(meter.update(&invalid, 3.0).is_err());
    }
}
