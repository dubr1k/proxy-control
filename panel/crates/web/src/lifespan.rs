//! The lifespan of `app.py:70-89`: startup work that runs **before** the first request is accepted
//! (Python: `access_enforcer.tick(force=True)`), then the background loops (fleet pusher, access
//! enforcer, metrics collector) as tasks; at shutdown every loop is told to stop, given
//! [`STOP_GRACE`] (5 s, `PUSHER_STOP_GRACE`) to finish, then aborted.
//!
//! The loops belong to other work packages: they implement [`BackgroundLoop`] and are registered in
//! `crate::wiring` (with the startup work) under the names the test hooks use — `pusher`,
//! `enforcer`, `metrics`. With the `test-hooks` feature the loops are not started (tests drive them
//! through `POST /__test/tick/<name>`), the startup work still runs.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tokio::sync::watch;

/// How long shutdown waits for the loops before cancelling them (`PUSHER_STOP_GRACE`).
pub const STOP_GRACE: Duration = Duration::from_secs(5);

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The stop request a loop watches (`stop()` sets the event).
#[derive(Debug, Clone)]
pub struct StopSignal {
    receiver: watch::Receiver<bool>,
}

impl StopSignal {
    /// True once shutdown began.
    pub fn is_stopped(&self) -> bool {
        *self.receiver.borrow()
    }

    /// Resolves when shutdown begins.
    pub async fn stopped(&mut self) {
        let _ = self.receiver.wait_for(|stopped| *stopped).await;
    }

    /// `asyncio.wait_for(stop.wait(), interval)`: true when stopped within `interval`.
    pub async fn wait(&mut self, interval: Duration) -> bool {
        tokio::time::timeout(interval, self.stopped()).await.is_ok()
    }
}

/// One background loop (`run_forever` + `tick`).
pub trait BackgroundLoop: Send + Sync + 'static {
    /// `pusher`, `enforcer` or `metrics`.
    fn name(&self) -> &'static str;

    /// `run_forever()`: ticks on its own schedule until `stop` fires.
    fn run(self: Arc<Self>, stop: StopSignal) -> BoxFuture<'static, ()>;

    /// One pass (`tick()`; the metrics loop also drains), with the hook's JSON options
    /// (`{"force": true}` for the enforcer).
    fn tick(&self, options: Value) -> BoxFuture<'_, Result<(), String>>;
}

/// Work to finish before serving (an error stops the start-up).
pub type StartupHook = Box<dyn FnOnce() -> BoxFuture<'static, Result<(), String>> + Send>;

/// The registry of loops and startup work.
#[derive(Default)]
pub struct Lifespan {
    loops: Mutex<Vec<Arc<dyn BackgroundLoop>>>,
    startup: Mutex<Vec<StartupHook>>,
}

impl std::fmt::Debug for Lifespan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> =
            self.loops.lock().map(|loops| loops.iter().map(|item| item.name()).collect()).unwrap_or_default();
        f.debug_struct("Lifespan").field("loops", &names).finish_non_exhaustive()
    }
}

impl Lifespan {
    /// Registers a loop (in the order Python starts them: pusher, enforcer, metrics).
    pub fn register_loop(&self, item: Arc<dyn BackgroundLoop>) {
        self.loops.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).push(item);
    }

    /// Registers work that must finish before serving.
    pub fn register_startup(&self, hook: StartupHook) {
        self.startup.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).push(hook);
    }

    /// The loop registered under `name`.
    pub fn find(&self, name: &str) -> Option<Arc<dyn BackgroundLoop>> {
        self.loops.lock().ok()?.iter().find(|item| item.name() == name).cloned()
    }

    /// Runs the startup work, then starts the loops (unless `paused`).
    pub async fn start(&self, paused: bool) -> Result<Supervisor, String> {
        let hooks: Vec<StartupHook> = std::mem::take(&mut *self.startup.lock().unwrap_or_else(|p| p.into_inner()));
        for hook in hooks {
            hook().await?;
        }
        let (sender, receiver) = watch::channel(false);
        let mut tasks = Vec::new();
        if !paused {
            let loops: Vec<Arc<dyn BackgroundLoop>> = self.loops.lock().map(|loops| loops.clone()).unwrap_or_default();
            for item in loops {
                let stop = StopSignal { receiver: receiver.clone() };
                tasks.push(tokio::spawn(item.run(stop)));
            }
        }
        Ok(Supervisor { sender, tasks })
    }
}

/// The running loops.
#[derive(Debug)]
pub struct Supervisor {
    sender: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Supervisor {
    /// Stops every loop: the stop signal, [`STOP_GRACE`] to finish, then cancellation.
    pub async fn shutdown(self) {
        self.shutdown_with_grace(STOP_GRACE).await;
    }

    pub async fn shutdown_with_grace(self, grace: Duration) {
        let _ = self.sender.send(true);
        let deadline = tokio::time::Instant::now() + grace;
        for mut task in self.tasks {
            if tokio::time::timeout_at(deadline, &mut task).await.is_err() {
                task.abort();
                let _ = task.await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counting {
        ticks: AtomicUsize,
        ignores_stop: bool,
    }

    impl BackgroundLoop for Counting {
        fn name(&self) -> &'static str {
            "pusher"
        }

        fn run(self: Arc<Self>, mut stop: StopSignal) -> BoxFuture<'static, ()> {
            Box::pin(async move {
                loop {
                    self.ticks.fetch_add(1, Ordering::SeqCst);
                    if self.ignores_stop {
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                    } else if stop.wait(Duration::from_millis(5)).await {
                        return;
                    }
                }
            })
        }

        fn tick(&self, _options: Value) -> BoxFuture<'_, Result<(), String>> {
            self.ticks.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn loops_stop_on_signal_and_stragglers_are_cancelled() {
        let lifespan = Lifespan::default();
        let polite = Arc::new(Counting { ticks: AtomicUsize::new(0), ignores_stop: false });
        let stubborn = Arc::new(Counting { ticks: AtomicUsize::new(0), ignores_stop: true });
        lifespan.register_loop(polite.clone());
        lifespan.register_loop(stubborn);
        let started = Arc::new(AtomicUsize::new(0));
        let seen = started.clone();
        lifespan.register_startup(Box::new(move || {
            Box::pin(async move {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }));
        let supervisor = lifespan.start(false).await.unwrap();
        assert_eq!(started.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_millis(30)).await;
        let begun = std::time::Instant::now();
        supervisor.shutdown_with_grace(Duration::from_millis(200)).await;
        assert!(begun.elapsed() < Duration::from_secs(2));
        assert!(polite.ticks.load(Ordering::SeqCst) >= 1);
        assert!(lifespan.find("pusher").is_some() && lifespan.find("metrics").is_none());
    }

    #[tokio::test]
    async fn paused_loops_do_not_run_but_tick_on_demand() {
        let lifespan = Lifespan::default();
        let item = Arc::new(Counting { ticks: AtomicUsize::new(0), ignores_stop: false });
        lifespan.register_loop(item.clone());
        let supervisor = lifespan.start(true).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(item.ticks.load(Ordering::SeqCst), 0);
        lifespan.find("pusher").unwrap().tick(Value::Null).await.unwrap();
        assert_eq!(item.ticks.load(Ordering::SeqCst), 1);
        supervisor.shutdown().await;
    }
}
