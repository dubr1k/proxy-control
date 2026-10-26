//! SSE framing against Python (`fixtures/sse.json`) and the stream loop of
//! `test_metrics_api.py` (`test_stream_*`).

mod common;

use std::sync::Arc;

use common::{fixture, Agent, LiveSources, Replay, TempDir};
use panel_core::clock::{FakeClock, SharedClock};
use panel_core::db::Database;
use panel_core::migrations::apply_migrations;
use panel_metrics::sse::{self, Alive, Build, EventStream, StreamRegistry, Timing};
use panel_metrics::{CollectorConfig, Metrics, MetricsCollector};
use serde_json::{json, Value};

#[test]
fn frames_are_byte_identical_to_python() {
    let recorded: Value = serde_json::from_str(&fixture("sse.json")).unwrap();
    assert_eq!(sse::retry_frame(), recorded["retry"].as_str().unwrap());
    assert_eq!(sse::PING, recorded["ping"].as_str().unwrap());
    for item in recorded["frames"].as_array().unwrap() {
        let payload: Value = serde_json::from_str(item["payload"].as_str().unwrap()).unwrap();
        assert_eq!(sse::frame(item["event"].as_str().unwrap(), &payload), item["frame"].as_str().unwrap());
    }
    let limits = &recorded["limits"];
    assert_eq!(sse::PER_SESSION as u64, limits["per_session"].as_u64().unwrap());
    assert_eq!(sse::GLOBAL as u64, limits["global"].as_u64().unwrap());
    assert_eq!(sse::PING_SECONDS, limits["ping"].as_f64().unwrap());
    assert_eq!(sse::MAX_AGE_SECONDS, limits["max_age"].as_f64().unwrap());
    assert_eq!(sse::RECHECK_SECONDS, limits["recheck"].as_f64().unwrap());
}

/// The rig of `test_metrics_api.py`: a collector over the agent double, three ticks done.
struct StreamRig {
    _dir: TempDir,
    clock: Arc<FakeClock>,
    metrics: Arc<Metrics>,
}

impl StreamRig {
    async fn new() -> Self {
        let dir = TempDir::new();
        let database = Database::open(dir.0.join("panel.db")).unwrap();
        apply_migrations(&database).unwrap();
        let clock = Arc::new(FakeClock::default());
        let agent = Agent::new(clock.clone());
        agent.set_protocol("trusttunnel", 1000.0, 3000.0, "kernel");
        agent.set_protocol("amneziawg", 200.0, 800.0, "interface");
        let managers = Replay::default();
        managers.set("mtproxy", Err("down".into()));
        let sources = Arc::new(LiveSources { agent, managers });
        let config = CollectorConfig {
            interval: 2.0,
            trusttunnel_enabled: false,
            amneziawg_enabled: false,
            naive_enabled: false,
            mieru_enabled: false,
        };
        let shared: SharedClock = clock.clone();
        let metrics = Metrics::new(true, 900, config, database, sources, shared);
        let rig = Self { _dir: dir, clock, metrics };
        for _ in 0..3 {
            rig.tick().await;
        }
        rig
    }

    fn collector(&self) -> &Arc<MetricsCollector> {
        self.metrics.collector().unwrap()
    }

    async fn tick(&self) {
        self.clock.advance(2.0);
        self.collector().tick().await.unwrap();
        self.collector().drain().await;
    }

    fn stream(&self, registry: &Arc<StreamRegistry>, key: &str, alive: bool) -> EventStream {
        let lease = registry.acquire(key).expect("a slot");
        let collector = self.collector().clone();
        let build: Build = Box::new(move || {
            let collector = collector.clone();
            Box::pin(async move { collector.snapshot().await })
        });
        let alive: Alive = Box::new(move || Box::pin(async move { alive }));
        let clock: SharedClock = self.clock.clone();
        let timing = Timing { poll: 0.005, ..Timing::default() };
        EventStream::new(lease, build, alive, self.collector().subscribe(), clock, timing)
    }
}

#[tokio::test]
async fn stream_frames_retry_snapshot_ping_and_bye() {
    let rig = StreamRig::new().await;
    let registry = Arc::new(StreamRegistry::default());
    let mut stream = rig.stream(&registry, "s1", true);
    assert_eq!(stream.next_frame().await.unwrap(), "retry: 3000\n\n");
    let snapshot = stream.next_frame().await.unwrap();
    assert!(snapshot.starts_with("event: snapshot\ndata: ") && snapshot.ends_with("\n\n"));
    let data: Value = serde_json::from_str(snapshot.split_once("data: ").unwrap().1.trim_end()).unwrap();
    assert_eq!(data["nodes"][0]["node_id"], json!("local"));
    assert_eq!(snapshot, sse::frame("snapshot", &rig.collector().snapshot().await.unwrap()));
    rig.clock.advance(16.0);
    assert_eq!(stream.next_frame().await.unwrap(), ": ping\n\n");
    rig.tick().await;
    assert!(stream.next_frame().await.unwrap().starts_with("event: snapshot"));
    rig.clock.advance(55.0 * 60.0);
    assert_eq!(stream.next_frame().await.unwrap(), "event: bye\ndata: {\"reason\":\"max_age\"}\n\n");
    assert!(stream.next_frame().await.is_none());
    assert_eq!(registry.open_streams(), 0);
}

#[tokio::test]
async fn stream_pings_every_fifteen_seconds_even_while_snapshots_flow() {
    let rig = StreamRig::new().await;
    let registry = Arc::new(StreamRegistry::default());
    let mut stream = rig.stream(&registry, "s1", true);
    assert_eq!(stream.next_frame().await.unwrap(), "retry: 3000\n\n");
    assert!(stream.next_frame().await.unwrap().starts_with("event: snapshot"));
    let mut frames = Vec::new();
    for _ in 0..9 {
        rig.clock.advance(2.0);
        rig.tick().await;
        frames.push(stream.next_frame().await.unwrap());
    }
    if let Ok(Some(frame)) = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next_frame()).await {
        frames.push(frame);
    }
    assert!(frames.iter().any(|f| f == ": ping\n\n"), "{frames:?}");
}

#[tokio::test]
async fn stream_ends_when_the_client_leaves_or_the_session_is_gone() {
    let rig = StreamRig::new().await;
    let registry = Arc::new(StreamRegistry::default());
    let mut stream = rig.stream(&registry, "s1", true);
    stream.next_frame().await;
    stream.next_frame().await;
    assert_eq!(registry.open_streams(), 1);
    drop(stream); // the client left: the body stream is dropped
    assert_eq!(registry.open_streams(), 0);
    let mut revoked = rig.stream(&registry, "s2", false);
    revoked.next_frame().await;
    revoked.next_frame().await;
    rig.clock.advance(61.0);
    assert_eq!(revoked.next_frame().await.unwrap(), "event: bye\ndata: {\"reason\":\"session_ended\"}\n\n");
    assert!(revoked.next_frame().await.is_none());
    assert_eq!(registry.open_streams(), 0);
}

#[test]
fn stream_limits_four_per_session_and_twenty_four_in_total() {
    let registry = Arc::new(StreamRegistry::default());
    let mut mine: Vec<_> = (0..4).map(|_| registry.acquire("a")).collect();
    assert!(mine.iter().all(Option::is_some) && registry.acquire("a").is_none());
    let others: Vec<_> = (0..20).map(|i| registry.acquire(&format!("s{i}"))).collect();
    assert!(others.iter().all(Option::is_some) && registry.acquire("late").is_none());
    let first = mine[0].as_mut().unwrap();
    first.release();
    first.release(); // a second release changes nothing
    assert_eq!(registry.open_streams(), 23);
    assert!(registry.acquire("late").is_some());
}
