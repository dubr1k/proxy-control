//! The collector and store against Python, tick by tick: every recorded scenario
//! (`fixtures/scenarios.jsonl`, one per test of `test_metrics_collector.py` /
//! `test_metrics_store.py`) is replayed with the same agent and manager answers, and every node
//! entry, ring, rollup table, prune count, history and summary body must be byte-identical.
//! Each test then checks the Python test's own assertions on the replayed state.

mod common;

use common::{fixture, Rig};
use indexmap::IndexMap;
use panel_core::pyjson;
use panel_metrics::store::{RollupKey, Slot};
use serde_json::{json, Value};

fn scenario(name: &str) -> Value {
    fixture("scenarios.jsonl")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("scenario json"))
        .find(|s| s["name"] == name)
        .unwrap_or_else(|| panic!("no recorded scenario {name}"))
}

fn text(value: &Value) -> String {
    pyjson::compact_utf8(value)
}

fn same(context: &str, got: &str, want: &str) {
    if got != want {
        let at = got.bytes().zip(want.bytes()).position(|(a, b)| a != b).unwrap_or(got.len().min(want.len()));
        let from = at.saturating_sub(120);
        panic!(
            "{context}: differs at byte {at}\n  rust:   …{}\n  python: …{}",
            &got[from..(at + 200).min(got.len())],
            &want[from..(at + 200).min(want.len())]
        );
    }
}

/// What a replay leaves behind for the test's own assertions.
struct Run {
    rig: Rig,
    latest: Vec<Value>,
    bodies: Vec<Value>,
}

async fn replay(name: &str) -> Run {
    let recorded = scenario(name);
    let rig = Rig::new(&recorded["flags"], recorded["start"].as_f64().unwrap());
    let mut latest = Vec::new();
    let mut bodies = Vec::new();
    for (index, op) in recorded["ops"].as_array().unwrap().iter().enumerate() {
        let context = format!("{name} op {index} ({})", op["op"]);
        match op["op"].as_str().unwrap() {
            "step" => {
                rig.sources.load(&op["calls"]);
                rig.step(op["advance"].as_f64().unwrap()).await;
                rig.sources.assert_consumed(&context);
                let collector = rig.collector();
                assert_eq!(collector.version(), op["version"].as_u64().unwrap(), "{context}: version");
                assert_eq!(collector.flushes(), op["flushes"].as_u64().unwrap(), "{context}: flushes");
                if let Some(want) = op.get("latest") {
                    let got = rig.latest().await;
                    same(&format!("{context} latest"), &text(&got), want.as_str().unwrap());
                    let snapshot = collector.snapshot().await.unwrap();
                    same(&format!("{context} snapshot"), &text(&snapshot), op["snapshot"].as_str().unwrap());
                    latest.push(got);
                }
            }
            "put" => {
                let mut rows: IndexMap<RollupKey, Slot> = IndexMap::new();
                let key = (
                    op["resolution"].as_i64().unwrap(),
                    op["bucket"].as_i64().unwrap(),
                    op["series"].as_str().unwrap().to_string(),
                );
                let slot = Slot {
                    sum: op["sum"].as_f64().unwrap(),
                    count: op["count"].as_i64().unwrap(),
                    max: op["max"].as_f64().unwrap(),
                    last: op["last"].as_f64().unwrap(),
                };
                rows.insert(key, slot);
                rig.metrics.store().write(&rows).expect("write");
            }
            "sql" => rig.sql(op["sql"].as_str().unwrap()),
            "history" => {
                let series: Vec<String> =
                    op["series"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect();
                let body = rig
                    .metrics
                    .store()
                    .history(&series, op["range"].as_str().unwrap(), op["points"].as_i64().unwrap())
                    .await
                    .expect("history");
                same(&context, &text(&body), op["body"].as_str().unwrap());
                bodies.push(body);
            }
            "summary" => {
                let body = rig.metrics.store().summary(op["range"].as_str().unwrap()).await.expect("summary");
                same(&context, &text(&body), op["body"].as_str().unwrap());
                bodies.push(body);
            }
            "prune" => {
                let removed = rig.metrics.store().prune(op["now"].as_f64()).await.expect("prune");
                assert_eq!(removed as u64, op["removed"].as_u64().unwrap(), "{context}: removed");
            }
            "rollups" => {
                let rows = rollups(&rig);
                same(&context, &text(&rows), &text(&op["rows"]));
                assert_eq!(
                    rig.metrics.store().flushed_until(),
                    op["flushed_until"].as_f64().unwrap(),
                    "{context}: flushed_until"
                );
            }
            "ring" => {
                let ring = rig.metrics.ring().lock().unwrap();
                let mut dump = serde_json::Map::new();
                for name in ring.series_names() {
                    let points: Vec<Value> = ring.all_points(&name).into_iter().map(|(t, v)| json!([t, v])).collect();
                    dump.insert(name, Value::Array(points));
                }
                same(&context, &text(&Value::Object(dump)), &text(&op["series"]));
            }
            "client_rates" => {
                let rates = rig.collector().client_rates(op["protocol"].as_str().unwrap()).await;
                same(&context, &text(&Value::Object(rates)), op["body"].as_str().unwrap());
            }
            "day_reads" => {
                assert_eq!(rig.metrics.store().day_reads(), op["count"].as_u64().unwrap(), "{context}");
            }
            other => panic!("{context}: unknown op {other}"),
        }
    }
    Run { rig, latest, bodies }
}

fn rollups(rig: &Rig) -> Value {
    let rows = rig
        .database
        .with_connection(|db| {
            let mut statement = db.prepare(
                "SELECT resolution,bucket,node_id,series,sum,count,max,last FROM metric_rollups ORDER BY 1,2,3,4",
            )?;
            let rows = statement
                .query_map([], |r| {
                    Ok(json!([
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, f64>(4)?,
                        r.get::<_, i64>(5)?,
                        r.get::<_, f64>(6)?,
                        r.get::<_, f64>(7)?
                    ]))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok::<_, panel_core::db::DbError>(rows)
        })
        .expect("rollups");
    Value::Array(rows)
}

fn cpu_rows(rig: &Rig, resolution: i64) -> Vec<(i64, f64, i64)> {
    rollups(rig)
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r[0] == resolution && r[3] == "host.cpu")
        .map(|r| (r[1].as_i64().unwrap(), r[4].as_f64().unwrap(), r[5].as_i64().unwrap()))
        .collect()
}

// ---- test_metrics_collector.py ----------------------------------------------------------------------

#[tokio::test]
async fn snapshot_shape_from_kernel_counters_and_managers() {
    let run = replay("snapshot_shape_from_kernel_counters_and_managers").await;
    let node = run.latest.last().unwrap();
    assert_eq!(
        (node["node_id"].as_str(), node["status"].as_str(), node["age_seconds"].as_f64()),
        (Some("local"), Some("ok"), Some(0.0))
    );
    assert_eq!(node["host"]["cpu_percent"], json!(12.5));
    let tt = &node["protocols"]["trusttunnel"];
    assert_eq!((&tt["source"], &tt["up_bps"], &tt["down_bps"]), (&json!("kernel"), &json!(1000.0), &json!(3000.0)));
    assert_eq!((&tt["sessions"], &tt["clients"]), (&json!(2), &json!(1)));
    assert_eq!(node["protocols"]["amneziawg"]["sessions"], json!(1));
    assert_eq!(node["protocols"]["mtproxy"]["sessions"], json!(3));
    assert_eq!(node["protocols"]["mieru"]["source"], json!("manager"));
    let top = node["top_clients"].as_array().unwrap();
    assert_eq!(top.iter().map(|r| r["username"].as_str().unwrap()).collect::<Vec<_>>(), ["alice", "erin"]);
    assert_eq!(top[1]["up_bps"], Value::Null);
    assert_eq!(top[1]["total_bps"], json!(1200.0));
}

#[tokio::test]
async fn kernel_rates_are_averaged_over_the_panel_tick_not_the_agents_last_second() {
    let run = replay("kernel_rates_are_averaged_over_the_panel_tick_not_the_agents_last_second").await;
    let naive = &run.latest[1]["protocols"]["naive"];
    assert_eq!((&naive["up_bps"], &naive["down_bps"]), (&json!(500.0), &json!(3000.0)));
    let reset = &run.latest[2]["protocols"]["naive"];
    assert_eq!((&reset["up_bps"], &reset["down_bps"]), (&json!(5.0), &json!(10.0)));
}

#[tokio::test]
async fn top_clients_are_named_through_the_client_store_and_capped_at_ten() {
    let run = replay("top_clients_are_named_through_the_client_store_and_capped_at_ten").await;
    let top = run.latest[1]["top_clients"].as_array().unwrap();
    assert_eq!(top.len(), 10);
    assert_eq!(top[0]["username"], json!("u13"));
    let last = run.latest[2]["top_clients"].as_array().unwrap();
    let named: Vec<_> = last.iter().filter(|r| r["username"] == "u0").collect();
    assert_eq!(named[0]["client_name"], json!("Alice Doe"));
}

#[tokio::test]
async fn without_kernel_counters_rates_come_from_manager_deltas() {
    let run = replay("without_kernel_counters_rates_come_from_manager_deltas").await;
    let tt = &run.latest[1]["protocols"]["trusttunnel"];
    assert_eq!(
        (&tt["source"], &tt["live"], &tt["up_bps"], &tt["down_bps"]),
        (&json!("manager"), &json!(true), &json!(1000.0), &json!(2000.0))
    );
    assert_eq!(run.latest[1]["kernel_counters"], json!("unavailable"));
    let naive = &run.latest[3]["protocols"]["naive"];
    assert_eq!(
        (&naive["source"], &naive["live"], &naive["down_bps"]),
        (&json!("manager"), &json!(false), &json!(900.0))
    );
}

#[tokio::test]
async fn naive_is_polled_every_15_seconds_even_when_the_kernel_counts_it() {
    let run = replay("naive_is_polled_every_15_seconds_even_when_the_kernel_counts_it").await;
    assert!((5..=8).contains(&run.rig.sources.count("naive")));
    let other = replay("naive_is_polled_every_15_seconds_without_the_kernel").await;
    assert!((5..=8).contains(&other.rig.sources.count("naive")));
    assert_eq!((other.rig.sources.count("trusttunnel"), other.rig.sources.count("mieru")), (0, 0));
}

#[tokio::test]
async fn naive_and_mieru_clients_get_their_own_rows_while_the_kernel_keeps_the_node_totals() {
    let run = replay("naive_and_mieru_clients_get_their_own_rows_while_the_kernel_keeps_the_node_totals").await;
    let node = run.latest.last().unwrap();
    assert_eq!(node["protocols"]["naive"]["source"], json!("kernel"));
    assert_eq!(node["protocols"]["mieru"]["source"], json!("kernel"));
    let rows = node["top_clients"].as_array().unwrap();
    let mia = rows.iter().find(|r| r["username"] == "mia").unwrap();
    let nina = rows.iter().find(|r| r["username"] == "nina").unwrap();
    assert_eq!((&mia["up_bps"], &mia["down_bps"], &mia["live"]), (&json!(200.0), &json!(1000.0), &json!(true)));
    assert_eq!((&nina["up_bps"], &nina["down_bps"], &nina["live"]), (&json!(75.0), &json!(750.0), &json!(false)));
}

#[tokio::test]
async fn mieru_rates_fall_back_to_the_manager_counters_without_the_kernel() {
    let run = replay("mieru_rates_fall_back_to_the_manager_counters_without_the_kernel").await;
    let mieru = &run.latest[1]["protocols"]["mieru"];
    assert_eq!(
        (&mieru["source"], &mieru["up_bps"], &mieru["down_bps"]),
        (&json!("manager"), &json!(100.0), &json!(1000.0))
    );
    let reset = &run.latest[2]["protocols"]["mieru"];
    assert_eq!((&reset["up_bps"], &reset["down_bps"]), (&json!(4.0), &json!(8.0)));
}

#[tokio::test]
async fn an_old_mieru_manager_without_the_route_leaves_the_rest_untouched() {
    let run = replay("an_old_mieru_manager_without_the_route_leaves_the_rest_untouched").await;
    let node = run.latest.last().unwrap();
    assert_eq!(
        (&node["protocols"]["mieru"]["source"], &node["protocols"]["mieru"]["live"]),
        (&json!("kernel"), &json!(true))
    );
    assert!(node["top_clients"].as_array().unwrap().iter().all(|r| r["protocol"] != "mieru"));
}

#[tokio::test]
async fn a_failing_manager_marks_only_its_protocol_unavailable() {
    let run = replay("a_failing_manager_marks_only_its_protocol_unavailable").await;
    assert_eq!(run.latest[1]["protocols"]["trusttunnel"]["available"], json!(true));
    let node = run.latest.last().unwrap();
    assert_eq!(node["protocols"]["trusttunnel"]["available"], json!(false));
    assert_eq!(node["protocols"]["trusttunnel"]["reason"], json!("manager_unavailable"));
    assert_eq!(node["protocols"]["amneziawg"]["available"], json!(true));
    assert_eq!(node["status"], json!("ok"));
}

#[tokio::test]
async fn an_unreachable_agent_makes_the_node_stale_with_its_age_and_records_nothing() {
    let run = replay("an_unreachable_agent_makes_the_node_stale_with_its_age_and_records_nothing").await;
    let node = run.latest.last().unwrap();
    assert_eq!(
        (&node["status"], &node["age_seconds"], &node["host"]["cpu_percent"]),
        (&json!("stale"), &json!(10.0), &json!(12.5))
    );
    assert_eq!(run.rig.metrics.ring().lock().unwrap().all_points("host.cpu").len(), 1);
    let fresh = replay("an_unreachable_agent_from_the_start_leaves_the_node_unavailable").await;
    let node = fresh.latest.last().unwrap();
    assert_eq!((&node["status"], &node["host"]), (&json!("unavailable"), &Value::Null));
}

#[tokio::test]
async fn kernel_counter_reset_adds_the_reading_not_a_negative_spike() {
    let run = replay("kernel_counter_reset_adds_the_reading_not_a_negative_spike").await;
    let values: Vec<f64> =
        run.rig.metrics.ring().lock().unwrap().all_points("trusttunnel.up_bytes").iter().map(|p| p.1).collect();
    assert_eq!(values.len(), 2);
    assert!(values.iter().all(|v| *v >= 0.0));
    assert_eq!(values[1], 200.0);
}

#[tokio::test]
async fn connections_come_from_the_agent_next_to_the_manager_sessions() {
    let run = replay("connections_come_from_the_agent_next_to_the_manager_sessions").await;
    let protocols = &run.latest.last().unwrap()["protocols"];
    assert_eq!(
        (&protocols["trusttunnel"]["connections"], &protocols["trusttunnel"]["sessions"]),
        (&json!(5), &json!(0))
    );
    assert_eq!(protocols["amneziawg"]["connections"], Value::Null);
    assert_eq!(protocols["mieru"]["connections"], Value::Null);
    let last = run.rig.metrics.ring().lock().unwrap().last("trusttunnel.connections").unwrap();
    assert_eq!(last.1, 5.0);
}

#[tokio::test]
async fn windowed_naive_rates_over_a_long_run() {
    replay("windowed_naive_rates_over_a_long_run").await;
}

// ---- test_metrics_store.py --------------------------------------------------------------------------

#[tokio::test]
async fn flush_writes_all_three_resolutions_in_one_pass_and_merges_the_next_flush() {
    let run = replay("flush_writes_all_three_resolutions_in_one_pass_and_merges_the_next_flush").await;
    assert_eq!(run.rig.collector().flushes(), 2);
    let rows = cpu_rows(&run.rig, 60);
    assert!(rows.iter().all(|(_, sum, count)| (*sum - *count as f64 * 10.0).abs() < 1e-9));
    for resolution in [60, 900, 3600] {
        assert!(!cpu_rows(&run.rig, resolution).is_empty());
    }
}

#[tokio::test]
async fn prune_drops_buckets_past_each_resolutions_retention() {
    let run = replay("prune_drops_buckets_past_each_resolutions_retention").await;
    for resolution in [60, 900, 3600] {
        assert_eq!(cpu_rows(&run.rig, resolution).len(), 1);
    }
}

#[tokio::test]
async fn prune_at_the_edges_of_each_retention() {
    replay("prune_at_the_edges_of_each_retention").await;
}

#[tokio::test]
async fn history_native_step_from_the_ring_with_gaps_where_the_agent_was_silent() {
    let run = replay("history_native_step_from_the_ring_with_gaps_where_the_agent_was_silent").await;
    let body = &run.bodies[0];
    assert_eq!((&body["source"], &body["resolution"], &body["step"]), (&json!("ring"), &json!(0), &json!(2)));
    let rows = body["series"]["host.cpu"].as_array().unwrap();
    assert_eq!(rows.last().unwrap()[1], json!(29.0));
    assert!(rows.len() > 400);
    assert!(rows.iter().filter(|r| r[1].is_null()).all(|r| r[2].is_null()));
}

#[tokio::test]
async fn history_downsamples_to_the_requested_points_keeping_the_peak() {
    let run = replay("history_downsamples_to_the_requested_points_keeping_the_peak").await;
    let body = &run.bodies[0];
    assert_eq!(body["step"], json!(10));
    let present: Vec<_> = body["series"]["host.cpu"].as_array().unwrap().iter().filter(|r| !r[1].is_null()).collect();
    assert_eq!(present.iter().map(|r| r[2].as_f64().unwrap()).fold(0.0, f64::max), 90.0);
    assert!(present.iter().map(|r| r[1].as_f64().unwrap()).fold(0.0, f64::max) < 90.0);
}

#[tokio::test]
async fn history_beyond_the_ring_comes_from_rollups_plus_the_unflushed_tail_exactly() {
    let run = replay("history_beyond_the_ring_comes_from_rollups_plus_the_unflushed_tail_exactly").await;
    let body = &run.bodies[0];
    assert_eq!((&body["source"], &body["resolution"], &body["step"]), (&json!("rollup"), &json!(60), &json!(60)));
    assert!(run.rig.metrics.store().flushed_until() < panel_core::clock::Clock::time(&*run.rig.clock));
}

#[tokio::test]
async fn history_picks_the_rollup_resolution_by_range() {
    let run = replay("history_picks_the_rollup_resolution_by_range").await;
    let want = [(60, 60), (60, 360), (900, 900), (900, 1800), (3600, 7200)];
    for (body, (resolution, step)) in run.bodies.iter().zip(want) {
        assert_eq!(
            (&body["source"], &body["resolution"], &body["step"]),
            (&json!("rollup"), &json!(resolution), &json!(step))
        );
        assert!(body["series"]["host.cpu"].as_array().unwrap().iter().all(|r| r[1].is_null()));
    }
}

#[tokio::test]
async fn summary_statistics_shares_and_peaks() {
    let run = replay("summary_statistics_shares_and_peaks").await;
    let body = &run.bodies[0];
    let now = 1_800_000_000 / 60 * 60;
    assert_eq!(body["host"]["cpu"], json!({"avg": 50.5, "p95": 95.0, "max": 100.0, "max_at": now - 60}));
    assert_eq!(body["host"]["swap"], json!({"avg": null, "p95": null, "max": null, "max_at": null}));
    let (tt, naive) = (&body["protocols"]["trusttunnel"], &body["protocols"]["naive"]);
    assert_eq!((&tt["up_bytes"], &tt["down_bytes"], &tt["total_bytes"]), (&json!(3000), &json!(6000), &json!(9000)));
    assert_eq!(
        (&naive["total_bytes"], &tt["share_percent"], &naive["share_percent"]),
        (&json!(2000), &json!(81.8), &json!(18.2))
    );
    assert_eq!(tt["avg_bps"], json!(700.0));
    assert_eq!((&tt["peak_bps"], &tt["peak_at"]), (&json!(2000.0), &json!(now - 240)));
    assert_eq!((&tt["connections_peak"], &tt["sessions_peak"]), (&json!(9), &json!(7)));
    assert_eq!(body["protocols"]["mieru"]["total_bytes"], Value::Null);
    assert_eq!(body["hours_of_day"], json!({}));
}

#[tokio::test]
async fn summary_hours_of_day_for_a_week() {
    let run = replay("summary_hours_of_day_for_a_week").await;
    let hours = run.bodies[0]["hours_of_day"]["trusttunnel"].as_array().unwrap();
    assert_eq!(hours.len(), 24);
    assert!(hours.iter().all(|v| !v.is_null()));
    assert_eq!(hours[3], json!(450.0));
    assert_eq!(run.bodies[0]["hours_of_day"]["mieru"], Value::Array(vec![Value::Null; 24]));
}

#[tokio::test]
async fn alerts_follow_the_plan_thresholds() {
    let run = replay("alerts_follow_the_plan_thresholds").await;
    let kinds = |node: &Value| -> Vec<(String, String)> {
        node["alerts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| (a["kind"].as_str().unwrap().into(), a["severity"].as_str().unwrap().into()))
            .collect()
    };
    let pair = |k: &str, s: &str| (k.to_string(), s.to_string());
    assert_eq!(kinds(&run.latest[0]), [pair("cpu", "warn"), pair("mem", "warn"), pair("swap", "warn")]);
    assert_eq!(kinds(&run.latest[1]), [pair("cpu", "critical"), pair("mem", "critical"), pair("swap", "warn")]);
    assert!(kinds(&run.latest[2]).is_empty());
}

#[tokio::test]
async fn a_silent_agent_raises_a_stale_alert_after_a_minute() {
    let run = replay("a_silent_agent_raises_a_stale_alert_after_a_minute").await;
    assert_eq!(run.latest[1]["alerts"], json!([]));
    let alert = &run.latest[2]["alerts"][0];
    assert_eq!(
        (&alert["kind"], &alert["severity"], &alert["since"]),
        (&json!("stale"), &json!("warn"), &json!(1_800_000_002))
    );
    assert_eq!(run.latest[3]["alerts"][0]["severity"], json!("critical"));
}

#[tokio::test]
async fn network_spike_is_three_times_the_p95_of_the_last_day() {
    let run = replay("network_spike_is_three_times_the_p95_of_the_last_day").await;
    assert_eq!(run.latest[0]["alerts"], json!([]));
    let alerts = run.latest[1]["alerts"].as_array().unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!((&alerts[0]["kind"], &alerts[0]["severity"]), (&json!("net_spike"), &json!("warn")));
}

#[tokio::test]
async fn the_spike_baseline_is_read_once_a_minute_not_every_tick() {
    let run = replay("the_spike_baseline_is_read_once_a_minute_not_every_tick").await;
    assert_eq!(run.latest.last().unwrap()["alerts"][0]["kind"], json!("net_spike"));
    assert!((1..=4).contains(&run.rig.metrics.store().day_reads()));
}
