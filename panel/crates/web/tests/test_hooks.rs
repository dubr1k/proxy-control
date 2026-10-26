//! The `/__test/*` contract of `panel/tests/harness/server.py` (built with `--features test-hooks`).

#![cfg(feature = "test-hooks")]

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use common::Client;
use panel_web::lifespan::{BackgroundLoop, BoxFuture, StopSignal};
use serde_json::{json, Value};

struct Recorder {
    options: std::sync::Mutex<Vec<Value>>,
}

impl BackgroundLoop for Recorder {
    fn name(&self) -> &'static str {
        "enforcer"
    }

    fn run(self: Arc<Self>, _stop: StopSignal) -> BoxFuture<'static, ()> {
        Box::pin(async {})
    }

    fn tick(&self, options: Value) -> BoxFuture<'_, Result<(), String>> {
        self.options.lock().unwrap().push(options);
        Box::pin(async { Ok(()) })
    }
}

#[test]
fn clock_hook_drives_wall_and_monotonic_time() {
    let panel = common::start(&[]);
    let mut client = Client::default();
    let set = client.send(&panel, "POST", "/__test/clock", &[], Some(r#"{"time": 1800000000.0}"#));
    assert_eq!(set.json(), json!({"time": 1800000000.0, "monotonic": 100000000.0}));
    let moved = client.send(&panel, "POST", "/__test/clock", &[], Some(r#"{"advance": 2.5}"#));
    assert_eq!(moved.json(), json!({"time": 1800000002.5, "monotonic": 100000002.5}));
    assert_eq!(client.send(&panel, "POST", "/__test/clock", &[], Some("{}")).status, 422);
    // The services that follow the clock see it (the API-key limiter, reveals, key expiry).
    use panel_core::clock::Clock as _;
    assert_eq!(panel.state.clock.now(), 1_800_000_002);
}

#[test]
fn tick_settle_and_bridge_hooks() {
    let panel = common::start(&[]);
    let recorder = Arc::new(Recorder { options: std::sync::Mutex::new(Vec::new()) });
    panel.state.lifespan.register_loop(recorder.clone());
    let mut client = Client::default();
    assert_eq!(
        client.send(&panel, "POST", "/__test/tick/enforcer", &[], Some(r#"{"force": true}"#)).json(),
        json!({"ok": true})
    );
    assert_eq!(client.send(&panel, "POST", "/__test/tick/enforcer", &[], None).status, 200);
    assert_eq!(*recorder.options.lock().unwrap(), vec![json!({"force": true}), json!({})]);
    assert_eq!(client.send(&panel, "POST", "/__test/tick/pusher", &[], None).status, 404, "not registered here");
    assert_eq!(client.send(&panel, "POST", "/__test/tick/bogus", &[], None).json(), json!({"detail": "unknown loop"}));

    let done = Arc::new(AtomicUsize::new(0));
    let seen = done.clone();
    let background = panel.state.background.clone();
    {
        let handle = panel.handle();
        let _entered = handle.enter();
        background.spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            seen.fetch_add(1, Ordering::SeqCst);
        });
    }
    assert_eq!(client.send(&panel, "POST", "/__test/settle", &[], None).status, 200);
    assert_eq!(done.load(Ordering::SeqCst), 1, "settle waited for the background work");

    assert_eq!(panel.state.test.bridge_answer(), None);
    assert_eq!(
        client.send(&panel, "POST", "/__test/probe-bridge", &[], Some(r#"{"answer": false}"#)).json(),
        json!({"answer": false})
    );
    assert_eq!(panel.state.test.bridge_answer(), Some(false));
    assert_eq!(client.send(&panel, "GET", "/__test/settle", &[], None).status, 405);
}
