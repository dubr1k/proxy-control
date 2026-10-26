//! Server-sent events for the live meters: framing, stream limits and the stream loop
//! (`metrics/sse.py`, inventory §5.3/§7.7). The frames are written as raw text (the first one
//! is a bare `retry:` frame, which `axum::response::sse` cannot emit).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use panel_core::clock::SharedClock;
use panel_core::pyjson;
use panel_model::protocols::BoxFuture;
use serde_json::Value;
use tokio::sync::watch;

pub const PER_SESSION: usize = 4;
pub const GLOBAL: usize = 24;
pub const RETRY_MS: u64 = 3000;
pub const PING_SECONDS: f64 = 15.0;
pub const MAX_AGE_SECONDS: f64 = 55.0 * 60.0;
pub const RECHECK_SECONDS: f64 = 60.0;
pub const POLL_SECONDS: f64 = 1.0;
pub const PING: &str = ": ping\n\n";

/// `retry: 3000\n\n`.
pub fn retry_frame() -> String {
    format!("retry: {RETRY_MS}\n\n")
}

/// `event: {event}\ndata: {json.dumps(payload, separators=(',', ':'), allow_nan=False)}\n\n`
/// (ASCII-escaped like `json.dumps`' default).
pub fn frame(event: &str, payload: &Value) -> String {
    format!("event: {event}\ndata: {}\n\n", pyjson::compact(payload))
}

/// Open streams per session and in total; a stream beyond either limit is refused.
#[derive(Debug)]
pub struct StreamRegistry {
    per_session: usize,
    total: usize,
    count: Mutex<HashMap<String, usize>>,
}

impl Default for StreamRegistry {
    fn default() -> Self {
        Self::new(PER_SESSION, GLOBAL)
    }
}

impl StreamRegistry {
    pub fn new(per_session: usize, total: usize) -> Self {
        Self { per_session, total, count: Mutex::new(HashMap::new()) }
    }

    fn counts(&self) -> std::sync::MutexGuard<'_, HashMap<String, usize>> {
        self.count.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// A slot for `key` (the session's or API key's token hash), or `None` beyond the limits.
    pub fn acquire(self: &Arc<Self>, key: &str) -> Option<Lease> {
        let mut counts = self.counts();
        let mine = counts.get(key).copied().unwrap_or(0);
        if mine >= self.per_session || counts.values().sum::<usize>() >= self.total {
            return None;
        }
        counts.insert(key.to_string(), mine + 1);
        Some(Lease { registry: Arc::clone(self), key: key.to_string(), open: true })
    }

    fn release(&self, key: &str) {
        let mut counts = self.counts();
        if let Some(count) = counts.get_mut(key) {
            *count -= 1;
            if *count == 0 {
                counts.remove(key);
            }
        }
    }

    pub fn open_streams(&self) -> usize {
        self.counts().values().sum()
    }
}

/// One open stream's slot; released once, explicitly or when dropped (client gone).
#[derive(Debug)]
pub struct Lease {
    registry: Arc<StreamRegistry>,
    key: String,
    open: bool,
}

impl Lease {
    pub fn release(&mut self) {
        if self.open {
            self.open = false;
            self.registry.release(&self.key);
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.release();
    }
}

/// The payload of the next snapshot frame (`None`: nothing to send yet).
pub type Build = Box<dyn Fn() -> BoxFuture<'static, Option<Value>> + Send + Sync>;
/// Whether the caller's session or API key is still valid.
pub type Alive = Box<dyn Fn() -> BoxFuture<'static, bool> + Send + Sync>;

/// Timing of a stream (the Python keyword arguments).
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    pub ping_seconds: f64,
    pub max_age: f64,
    pub recheck_seconds: f64,
    pub poll: f64,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            ping_seconds: PING_SECONDS,
            max_age: MAX_AGE_SECONDS,
            recheck_seconds: RECHECK_SECONDS,
            poll: POLL_SECONDS,
        }
    }
}

/// The stream loop (`event_stream`): `retry`, a snapshot at once and after every collector
/// tick, a `: ping` every `ping_seconds` (also between snapshots), `event: bye` at the age
/// limit or when the session is gone. The client leaving drops the stream and its lease.
pub struct EventStream {
    lease: Lease,
    build: Build,
    alive: Alive,
    events: watch::Receiver<u64>,
    clock: SharedClock,
    timing: Timing,
    started: f64,
    last_ping: f64,
    last_check: f64,
    seen: Option<u64>,
    begun: bool,
    done: bool,
}

impl EventStream {
    pub fn new(
        lease: Lease,
        build: Build,
        alive: Alive,
        events: watch::Receiver<u64>,
        clock: SharedClock,
        timing: Timing,
    ) -> Self {
        Self {
            lease,
            build,
            alive,
            events,
            clock,
            timing,
            started: 0.0,
            last_ping: 0.0,
            last_check: 0.0,
            seen: None,
            begun: false,
            done: false,
        }
    }

    fn finish(&mut self) {
        self.done = true;
        self.lease.release();
    }

    /// The next frame, or `None` when the stream is over.
    pub async fn next_frame(&mut self) -> Option<String> {
        if self.done {
            return None;
        }
        if !self.begun {
            self.begun = true;
            let now = self.clock.monotonic();
            (self.started, self.last_ping, self.last_check) = (now, now, now);
            return Some(retry_frame());
        }
        loop {
            let now = self.clock.monotonic();
            if now - self.started >= self.timing.max_age {
                self.finish();
                return Some(frame("bye", &serde_json::json!({"reason": "max_age"})));
            }
            if now - self.last_check >= self.timing.recheck_seconds {
                self.last_check = now;
                if !(self.alive)().await {
                    self.finish();
                    return Some(frame("bye", &serde_json::json!({"reason": "session_ended"})));
                }
            }
            let current = *self.events.borrow_and_update();
            if Some(current) != self.seen {
                if let Some(payload) = (self.build)().await {
                    self.seen = Some(current);
                    return Some(frame("snapshot", &payload));
                }
            }
            if now - self.last_ping >= self.timing.ping_seconds {
                self.last_ping = now;
                return Some(PING.to_string());
            }
            let wait = Duration::from_secs_f64(self.timing.poll.max(0.0));
            if let Ok(Err(_)) = tokio::time::timeout(wait, self.events.changed()).await {
                tokio::time::sleep(wait).await; // the collector is gone: keep the poll cadence
            }
        }
    }

    /// The frames as a body stream.
    pub fn into_stream(
        self,
    ) -> impl futures_util::Stream<Item = Result<axum::body::Bytes, std::convert::Infallible>> + Send {
        futures_util::stream::unfold(self, |mut stream| async move {
            let frame = stream.next_frame().await?;
            Some((Ok(axum::body::Bytes::from(frame)), stream))
        })
    }
}
