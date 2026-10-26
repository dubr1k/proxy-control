//! Wall and monotonic time behind one trait, so background loops and rate limits can be tested
//! without sleeping.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Python's `time.time()` / `time.monotonic()` pair.
pub trait Clock: Send + Sync + 'static {
    /// Seconds since the Unix epoch (`time.time()`).
    fn time(&self) -> f64;

    /// Seconds of a clock that never goes backwards (`time.monotonic()`); only differences mean
    /// anything.
    fn monotonic(&self) -> f64;

    /// `int(time.time())`: whole epoch seconds, truncated — what every timestamp column stores.
    fn now(&self) -> i64 {
        self.time() as i64
    }
}

/// A clock shared between the services of one process.
pub type SharedClock = Arc<dyn Clock>;

/// The real clocks: `SystemTime` and `CLOCK_MONOTONIC` (the clock behind Python's
/// `time.monotonic()` on Linux, so values are seconds since boot, never near zero).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl SystemClock {
    /// A [`SharedClock`] of the real time.
    pub fn shared() -> SharedClock {
        Arc::new(SystemClock)
    }
}

impl Clock for SystemClock {
    fn time(&self) -> f64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(elapsed) => elapsed.as_secs_f64(),
            Err(before) => -before.duration().as_secs_f64(),
        }
    }

    fn monotonic(&self) -> f64 {
        let mut spec = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: `spec` is a valid, writable timespec; CLOCK_MONOTONIC is always available.
        let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut spec) };
        assert_eq!(rc, 0, "clock_gettime(CLOCK_MONOTONIC) failed");
        spec.tv_sec as f64 + spec.tv_nsec as f64 / 1e9
    }
}

/// The tests' clock (`panel/metrics/fakes.py` `FakeClock`): time moves only when told to, and
/// `monotonic() == time() - 1_700_000_000`.
#[derive(Debug)]
pub struct FakeClock {
    now: Mutex<f64>,
}

impl FakeClock {
    /// The offset between the fake wall clock and the fake monotonic clock.
    pub const MONOTONIC_OFFSET: f64 = 1_700_000_000.0;

    /// A fake clock reading `start` epoch seconds.
    pub fn new(start: f64) -> Self {
        Self { now: Mutex::new(start) }
    }

    /// Moves time forward (or back, with a negative value).
    pub fn advance(&self, seconds: f64) {
        *self.lock() += seconds;
    }

    /// Sets the wall clock.
    pub fn set(&self, now: f64) {
        *self.lock() = now;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, f64> {
        self.now.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Default for FakeClock {
    /// Python's default start, `1_800_000_000.0`.
    fn default() -> Self {
        Self::new(1_800_000_000.0)
    }
}

impl Clock for FakeClock {
    fn time(&self) -> f64 {
        *self.lock()
    }

    fn monotonic(&self) -> f64 {
        *self.lock() - Self::MONOTONIC_OFFSET
    }
}

impl<C: Clock + ?Sized> Clock for Arc<C> {
    fn time(&self) -> f64 {
        (**self).time()
    }

    fn monotonic(&self) -> f64 {
        (**self).monotonic()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_clock_moves_only_when_told() {
        let clock = FakeClock::default();
        assert_eq!(clock.time(), 1_800_000_000.0);
        assert_eq!(clock.monotonic(), 100_000_000.0);
        clock.advance(2.5);
        assert_eq!(clock.time(), 1_800_000_002.5);
        assert_eq!(clock.monotonic(), 100_000_002.5);
        assert_eq!(clock.now(), 1_800_000_002);
    }

    #[test]
    fn system_clock_is_sane() {
        let clock = SystemClock;
        assert!(clock.time() > 1_700_000_000.0);
        let first = clock.monotonic();
        assert!(first > 0.0);
        assert!(clock.monotonic() >= first);
        let shared: SharedClock = SystemClock::shared();
        assert!(shared.now() > 1_700_000_000);
    }
}
