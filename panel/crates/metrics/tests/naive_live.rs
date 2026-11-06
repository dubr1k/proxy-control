mod common;
use common::Rig;
use serde_json::{json, Value};
fn sample(epoch: &str, at: u64, up: u64, down: u64) -> Value {
    json!({"schema":1,"semantics":"authenticated_connect_payload","process_epoch":epoch,
        "sampled_at_ms":at,"upload_bytes":up,"download_bytes":down,"active_tunnels":2})
}
fn set(rig: &Rig, reading: Result<Value, String>) {
    rig.sources.fixed.lock().unwrap().insert("naive_live".into(), reading);
}
#[tokio::test]
async fn live_graph_is_client_only_before_close_and_quota_poll_remains_separate() {
    let rig = Rig::with(json!({"naive_enabled":true}));
    {
        let mut fixed = rig.sources.fixed.lock().unwrap();
        fixed.insert(
            "agent".into(),
            Ok(json!({"kernel_counters":"ok","protocols":{"naive":{
            "up_bytes":9000000,"down_bytes":9000000,"up_bps":900000,"down_bps":900000}}})),
        );
        fixed.insert("mtproxy".into(), Ok(json!([])));
        fixed.insert("naive".into(), Ok(json!({"users":[]})));
    }
    set(&rig, Ok(sample("one", 1000, 10, 20)));
    rig.step(2.0).await;
    let first = rig.latest().await;
    assert_eq!(first["protocols"]["naive"]["source"], "naive_connect");
    assert!(first["protocols"]["naive"]["up_bps"].is_null());
    set(&rig, Ok(sample("one", 3000, 110, 420)));
    rig.step(2.0).await;
    let live = rig.latest().await;
    assert_eq!(live["protocols"]["naive"]["up_bps"], 50.0);
    assert_eq!(live["protocols"]["naive"]["down_bps"], 200.0);
    assert_eq!(live["protocols"]["naive"]["active_tunnels"], 2);
    assert_eq!(rig.sources.count("naive"), 1); // log collector has NOT been polled every 2s
                                               // Record last received sample once, without adding completed logs or kernel bytes.
    set(&rig, Ok(sample("one", 5000, 110, 420)));
    rig.step(2.0).await;
    {
        let ring = rig.metrics.ring();
        let ring = ring.lock().unwrap();
        assert!(ring.all_points("naive.up_bps").is_empty());
        assert_eq!(ring.all_points("naive_connect.up_bps").last().unwrap().1, 50.0);
        assert_eq!(ring.all_points("naive_connect.up_bytes").iter().map(|p| p.1).sum::<f64>(), 100.0);
    }
    set(&rig, Err("unavailable".into()));
    rig.step(2.0).await;
    assert_eq!(rig.latest().await["protocols"]["naive"]["available"], false);
    assert!(rig.latest().await["protocols"]["naive"]["up_bps"].is_null());
    set(&rig, Ok(sample("two", 10, 800000, 900000)));
    rig.step(2.0).await;
    assert!(rig.latest().await["protocols"]["naive"]["up_bps"].is_null());
    let summary = rig.metrics.store().summary("15m").await.unwrap();
    assert!(summary["protocols"].get("naive_connect").is_some());
}
