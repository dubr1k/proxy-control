//! The accounting collector, ported from `tests/test_naive_traffic.py`, and the proof that a
//! database written by the Python collector is read and continued.

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::error::{Error, Result};
use crate::tests::tempdir;
use crate::traffic::{Options, TrafficCollector};

/// `record(user, upload, download, **overrides)`: one compact access-log line.
fn record_with(user: &str, upload: Value, download: Value, overrides: &[(&str, Value)]) -> String {
    let mut value = Map::new();
    value.insert("request".into(), json!({"method": "CONNECT"}));
    value.insert("status".into(), json!(200));
    value.insert("user_id".into(), json!(user));
    value.insert("bytes_read".into(), upload);
    value.insert("size".into(), download);
    for (key, item) in overrides {
        value.insert(key.to_string(), item.clone());
    }
    pc_common::json::dumps(&Value::Object(value), &crate::pyjson::COMPACT) + "\n"
}

fn record(upload: i64, download: i64) -> String {
    record_with("alice", json!(upload), json!(download), &[])
}

fn users(names: &[&str]) -> crate::traffic::ManagedUsers {
    let set: HashSet<String> = names.iter().map(|s| s.to_string()).collect();
    Box::new(move || Ok(set.clone()))
}

fn open(log: &Path, db: &Path, names: &[&str], options: Options) -> TrafficCollector {
    TrafficCollector::new(log, db, users(names), options).unwrap()
}

/// `collector(tmp_path)`: an empty 0600 log in `logs/`, users alice and bob.
fn collector(dir: &Path) -> (TrafficCollector, PathBuf) {
    let log = dir.join("logs/access.json");
    std::fs::create_dir_all(log.parent().unwrap()).unwrap();
    std::fs::write(&log, "").unwrap();
    std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o600)).unwrap();
    (open(&log, &dir.join("traffic.sqlite3"), &["alice", "bob"], Options::default()), log)
}

fn append(path: &Path, text: &str) {
    let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    std::io::Write::write_all(&mut file, text.as_bytes()).unwrap();
}

fn total(traffic: &TrafficCollector) -> Value {
    traffic.list_traffic().unwrap()["aggregate"]["total_bytes"].clone()
}

fn small(max_line: u64, max_read: u64) -> Options {
    Options { max_line_bytes: max_line, max_read_bytes: max_read, ..Default::default() }
}

fn runtime_message(err: Error) -> String {
    assert!(err.is_runtime(), "{err:?}");
    err.message().to_string()
}

#[test]
fn exact_connect_directions_are_durable_and_idempotent() {
    let dir = tempdir("traffic-exact");
    let (traffic, log) = collector(&dir);
    std::fs::write(&log, record(12345, 12345)).unwrap();
    assert_eq!(traffic.collect().unwrap(), 1);
    let mut row = traffic.list_traffic().unwrap()["users"][0].clone();
    row["period_start"] = json!("x");
    row["updated_at"] = json!("x");
    assert_eq!(
        row,
        json!({"username": "alice", "upload_bytes": 12345, "download_bytes": 12345, "total_bytes": 24690,
               "period_start": "x", "updated_at": "x", "upload_bytes_decimal": "12345",
               "download_bytes_decimal": "12345", "total_bytes_decimal": "24690"})
    );
    assert_eq!(traffic.collect().unwrap(), 0);
    traffic.close();
    let restarted = open(&log, &dir.join("traffic.sqlite3"), &["alice", "bob"], Options::default());
    assert_eq!(restarted.collect().unwrap(), 0);
    assert_eq!(total(&restarted), 24690);
}

#[test]
fn partial_lines_wait_for_completion() {
    let dir = tempdir("traffic-partial");
    let (traffic, log) = collector(&dir);
    let line = record(7, 9);
    std::fs::write(&log, &line[..line.len() - 1]).unwrap();
    assert_eq!(traffic.collect().unwrap(), 0);
    assert_eq!(traffic.list_traffic().unwrap()["pending"], true);
    append(&log, "\n");
    assert_eq!(traffic.collect().unwrap(), 1);
    assert_eq!(traffic.list_traffic().unwrap()["users"][0]["total_bytes"], 16);
}

#[test]
fn record_larger_than_read_budget_is_durably_quarantined_then_progresses() {
    let dir = tempdir("traffic-quarantine");
    let log = dir.join("logs/access.json");
    std::fs::create_dir_all(log.parent().unwrap()).unwrap();
    std::fs::write(&log, "").unwrap();
    let db = dir.join("traffic.sqlite3");
    let traffic = open(&log, &db, &["alice"], small(128, 160));
    std::fs::write(&log, "x".repeat(200) + "\n" + &record(7, 9)).unwrap();
    assert_eq!(traffic.collect().unwrap(), 0);
    assert_eq!(traffic.list_traffic().unwrap()["pending"], true);
    traffic.close();
    let restarted = open(&log, &db, &["alice"], small(128, 160));
    let accepted: u64 = (0..4).map(|_| restarted.collect().unwrap()).sum();
    assert_eq!(accepted, 1);
    assert_eq!(total(&restarted), 16);
    assert_eq!(restarted.collect().unwrap(), 0);
    assert_eq!(total(&restarted), 16);
    assert_eq!(restarted.list_traffic().unwrap()["pending"], false);
}

#[test]
fn rename_rotation_is_processed_once() {
    let dir = tempdir("traffic-rename");
    let (traffic, log) = collector(&dir);
    std::fs::write(&log, record(1, 2)).unwrap();
    assert_eq!(traffic.collect().unwrap(), 1);
    std::fs::rename(&log, log.with_file_name("access-2026-08-14T15-00-00.000-size.json")).unwrap();
    std::fs::write(&log, record(3, 4)).unwrap();
    assert_eq!(traffic.collect().unwrap(), 1);
    assert_eq!(traffic.collect().unwrap(), 0);
    assert_eq!(total(&traffic), 10);
}

fn path_rows(db: &Path) -> Vec<(i64, String)> {
    let database = Connection::open(db).unwrap();
    let mut statement = database.prepare("SELECT inode,path FROM traffic_files").unwrap();
    let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
    rows.map(|r| r.unwrap()).collect()
}

#[test]
fn active_hardlink_alias_counts_once_and_does_not_consume_rotation_or_verify_budget() {
    let dir = tempdir("traffic-hardlink-active");
    let log = dir.join("logs/access.json");
    std::fs::create_dir_all(log.parent().unwrap()).unwrap();
    let line = record(7, 11);
    std::fs::write(&log, &line).unwrap();
    std::fs::hard_link(&log, log.with_file_name("access-2026-08-14T15-00-00.000-size.json")).unwrap();
    let db = dir.join("traffic.sqlite3");
    let options = Options { max_verify_bytes: line.len() as u64, max_rotations: 0, ..small(128, 256) };
    let traffic = open(&log, &db, &["alice"], options);
    assert_eq!(traffic.collect().unwrap(), 1);
    assert_eq!(traffic.collect().unwrap(), 0);
    assert_eq!(total(&traffic), 18);
    assert_eq!(path_rows(&db)[0].1, log.display().to_string());
}

#[test]
fn rotated_hardlink_aliases_use_oldest_stable_path_and_one_rotation_slot() {
    let dir = tempdir("traffic-hardlink-rotated");
    let log = dir.join("logs/access.json");
    std::fs::create_dir_all(log.parent().unwrap()).unwrap();
    std::fs::write(&log, "").unwrap();
    let newer = log.with_file_name("access-2026-08-14T15-00-01.000-size.json");
    let older = log.with_file_name("access-2026-08-14T15-00-00.000-size.json");
    std::fs::write(&newer, record(2, 3)).unwrap();
    std::fs::hard_link(&newer, &older).unwrap();
    let db = dir.join("traffic.sqlite3");
    let traffic = open(&log, &db, &["alice"], Options { max_rotations: 1, ..small(128, 256) });
    assert_eq!(traffic.collect().unwrap(), 1);
    assert_eq!(traffic.collect().unwrap(), 0);
    let inode = std::fs::metadata(&older).unwrap().ino() as i64;
    let path = path_rows(&db).into_iter().find(|(i, _)| *i == inode).unwrap().1;
    assert_eq!(path, older.display().to_string());
}

#[test]
fn rotation_at_prune_identity_rescan_boundary_is_not_replayed() {
    for rotate_after_scan in [false, true] {
        let dir = tempdir(&format!("traffic-prune-boundary-{rotate_after_scan}"));
        let (traffic, log) = collector(&dir);
        std::fs::write(&log, record(1, 2)).unwrap();
        let rotated = log.with_file_name("access-2026-08-14T15-00-00.000-size.json");
        let (from, to) = (log.clone(), rotated.clone());
        let rotate: crate::traffic::Hook = Box::new(move || {
            std::fs::rename(&from, &to).unwrap();
            std::fs::write(&from, "").unwrap();
        });
        {
            let mut probes = traffic.probes.lock().unwrap();
            if rotate_after_scan {
                probes.after_present_identities = Some(rotate);
            } else {
                probes.before_present_identities = Some(rotate);
            }
        }
        assert_eq!(traffic.collect().unwrap(), 1);
        *traffic.probes.lock().unwrap() = Default::default();
        assert_eq!(traffic.collect().unwrap(), 0);
        assert_eq!(total(&traffic), 3);
    }
}

#[test]
fn new_active_created_after_discovery_is_deferred_to_next_pass() {
    let dir = tempdir("traffic-deferred");
    let (traffic, log) = collector(&dir);
    std::fs::write(&log, record(1, 2)).unwrap();
    let rotated = log.with_file_name("access-2026-08-14T15-00-00.000-size.json");
    let done = Arc::new(AtomicBool::new(false));
    let (flag, from, to) = (done.clone(), log.clone(), rotated.clone());
    traffic.probes.lock().unwrap().before_collect_file = Some(Box::new(move |_| {
        if !flag.swap(true, Ordering::SeqCst) {
            std::fs::rename(&from, &to).unwrap();
            std::fs::write(&from, record(3, 4)).unwrap();
        }
    }));
    assert!(runtime_message(traffic.collect().unwrap_err()).contains("changed during discovery"));
    traffic.probes.lock().unwrap().before_collect_file = None;
    assert_eq!(traffic.collect().unwrap(), 2);
    assert_eq!(traffic.collect().unwrap(), 0);
    assert_eq!(total(&traffic), 10);
}

#[test]
fn timberjack_rotation_names_are_processed_oldest_first_and_unrelated_files_ignored() {
    let dir = tempdir("traffic-timberjack");
    let (traffic, log) = collector(&dir);
    std::fs::write(log.with_file_name("access-2026-08-14T15-00-00.000-size.json"), record(1, 2)).unwrap();
    std::fs::write(log.with_file_name("access-2026-08-14T15-00-01.123-rotate.json"), record(3, 4)).unwrap();
    std::fs::write(&log, record(5, 6)).unwrap();
    for unrelated in
        ["access.json.1", "access-2026-08-14T15-00-01.12-size.json", "other-2026-08-14T15-00-01.123-size.json"]
    {
        std::fs::write(log.with_file_name(unrelated), record(100, 100)).unwrap();
    }
    assert_eq!(traffic.collect().unwrap(), 3);
    assert_eq!(total(&traffic), 21);
}

#[test]
fn matching_timberjack_rotation_symlink_fails_closed() {
    let dir = tempdir("traffic-symlink-rotation");
    let (traffic, log) = collector(&dir);
    let target = dir.join("outside.json");
    std::fs::write(&target, record(10, 20)).unwrap();
    std::os::unix::fs::symlink(&target, log.with_file_name("access-2026-08-14T15-00-00.000-size.json")).unwrap();
    assert!(runtime_message(traffic.collect().unwrap_err()).contains("unavailable or unsafe"));
}

#[test]
fn same_size_same_tail_copytruncate_fails_closed() {
    let dir = tempdir("traffic-copytruncate");
    let (traffic, log) = collector(&dir);
    let first = record_with("alice", json!(1), json!(2), &[("padding", json!("x".repeat(160)))]);
    let replacement = record_with("alice", json!(7), json!(8), &[("padding", json!("x".repeat(160)))]);
    assert_eq!(first.len(), replacement.len());
    assert_eq!(first[first.len() - 64..], replacement[replacement.len() - 64..]);
    std::fs::write(&log, &first).unwrap();
    assert_eq!(traffic.collect().unwrap(), 1);
    std::fs::write(&log, &replacement).unwrap();
    // The decision rests on persisted content, not mutable metadata.
    let info = std::fs::metadata(&log).unwrap();
    let database = Connection::open(dir.join("traffic.sqlite3")).unwrap();
    database
        .execute(
            "UPDATE traffic_files SET observed_mtime_ns=?,observed_ctime_ns=?",
            rusqlite::params![
                info.mtime() * 1_000_000_000 + info.mtime_nsec(),
                info.ctime() * 1_000_000_000 + info.ctime_nsec()
            ],
        )
        .unwrap();
    drop(database);
    assert!(runtime_message(traffic.collect().unwrap_err()).contains("rename-only"));
    assert_eq!(total(&traffic), 3);
}

#[test]
fn same_inode_middle_rewrite_with_identical_sampled_ends_fails_closed() {
    let dir = tempdir("traffic-middle-rewrite");
    let (traffic, log) = collector(&dir);
    let padding = |middle: &str| json!(format!("{}{}{}", "a".repeat(5000), middle.repeat(100), "z".repeat(5000)));
    let first = record_with("alice", json!(1), json!(2), &[("padding", padding("X"))]);
    let replacement = record_with("alice", json!(1), json!(2), &[("padding", padding("Y"))]);
    assert!(first.len() == replacement.len() && first.len() > 8192);
    assert_eq!(first[..4096], replacement[..4096]);
    assert_eq!(first[first.len() - 4096..], replacement[replacement.len() - 4096..]);
    std::fs::write(&log, &first).unwrap();
    assert_eq!(traffic.collect().unwrap(), 1);
    std::fs::write(&log, &replacement).unwrap();
    assert!(runtime_message(traffic.collect().unwrap_err()).contains("rename-only"));
    assert_eq!(total(&traffic), 3);
}

#[test]
fn production_retention_budget_reverifies_near_full_rotation_and_active_log() {
    let dir = tempdir("traffic-production");
    let log = dir.join("logs/access.json");
    std::fs::create_dir_all(log.parent().unwrap()).unwrap();
    let base = record_with("alice", json!(12345), json!(12345), &[("padding", json!(""))]);
    let one_mib =
        record_with("alice", json!(12345), json!(12345), &[("padding", json!("x".repeat(1024 * 1024 - base.len())))]);
    assert_eq!(one_mib.len(), 1024 * 1024);
    let near_full = one_mib.repeat(9);
    std::fs::write(log.with_file_name("access-2026-08-14T15-00-00.000-size.json"), &near_full).unwrap();
    std::fs::write(&log, &near_full).unwrap();
    let state = dir.join("users.json");
    std::fs::write(
        &state,
        json!({"version": 1, "host": "naive.example.com",
               "users": [{"username": "alice", "password": "secret", "enabled": true}], "tombstones": []})
        .to_string(),
    )
    .unwrap();
    let env: HashMap<String, String> = [
        ("NAIVE_PUBLIC_HOST", "naive.example.com".to_string()),
        ("NAIVE_TRAFFIC_LOG", log.display().to_string()),
        ("NAIVE_TRAFFIC_DATABASE", dir.join("traffic.sqlite3").display().to_string()),
        ("NAIVE_CADDYFILE", dir.join("Caddyfile").display().to_string()),
        ("NAIVE_STATE_FILE", state.display().to_string()),
        ("NAIVE_BACKUP_DIR", dir.join("backups").display().to_string()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    let manager = crate::config::build_manager(&crate::config::from_env(&env).unwrap()).unwrap();
    let traffic = manager.traffic().unwrap();
    assert_eq!(traffic.options.max_rotations, 10);
    assert_eq!(traffic.options.max_verify_bytes, 128 * 1024 * 1024);
    assert_eq!(traffic.options.expected_retained_bytes, Some(110 * 1024 * 1024));
    assert_eq!(traffic.collect().unwrap(), 18);
    assert_eq!(traffic.collect().unwrap(), 0);
    assert_eq!(traffic.health().unwrap()["ready"], true);
    traffic.close();
}

#[test]
fn declared_retention_larger_than_verify_budget_is_rejected_at_startup() {
    let dir = tempdir("traffic-retention");
    let log = dir.join("access.json");
    std::fs::write(&log, "").unwrap();
    let options = Options { max_verify_bytes: 109, expected_retained_bytes: Some(110), ..Default::default() };
    let err = TrafficCollector::new(&log, &dir.join("traffic.sqlite3"), users(&[]), options).err().unwrap();
    assert!(matches!(&err, Error::Value(m) if m.contains("retained accounting footprint")), "{err:?}");
}

#[test]
fn consumed_prefix_larger_than_request_budget_fails_closed() {
    let dir = tempdir("traffic-verify-budget");
    let log = dir.join("logs/access.json");
    std::fs::create_dir_all(log.parent().unwrap()).unwrap();
    std::fs::write(&log, record_with("alice", json!(12345), json!(12345), &[("padding", json!("x".repeat(300)))]))
        .unwrap();
    let options = Options { max_verify_bytes: 300, ..small(512, 600) };
    let traffic = open(&log, &dir.join("traffic.sqlite3"), &["alice"], options);
    assert_eq!(traffic.collect().unwrap(), 1);
    append(&log, &record_with("alice", json!(1), json!(2), &[("padding", json!("y".repeat(300)))]));
    assert!(runtime_message(traffic.collect().unwrap_err()).contains("verification budget"));
    assert_eq!(traffic.health().unwrap()["ready"], false);
}

#[test]
fn prefix_verification_budget_is_shared_across_all_candidates() {
    let dir = tempdir("traffic-shared-budget");
    let log = dir.join("logs/access.json");
    std::fs::create_dir_all(log.parent().unwrap()).unwrap();
    let line = record(1, 2).trim_end_matches('\n').to_string() + &" ".repeat(10) + "\n";
    assert_eq!(line.len(), 98);
    std::fs::write(log.with_file_name("access-2026-08-14T15-00-00.000-size.json"), &line).unwrap();
    std::fs::write(&log, &line).unwrap();
    let traffic =
        open(&log, &dir.join("traffic.sqlite3"), &["alice"], Options { max_verify_bytes: 98, ..small(128, 512) });
    assert_eq!(traffic.collect().unwrap(), 2);
    let verified = Arc::new(Mutex::new(Vec::new()));
    let sink = verified.clone();
    traffic.probes.lock().unwrap().hash_prefix = Some(Box::new(move |length| sink.lock().unwrap().push(length)));
    assert!(runtime_message(traffic.collect().unwrap_err()).contains("verification budget"));
    assert_eq!(*verified.lock().unwrap(), [98]);
    assert_eq!(total(&traffic), 6);
}

#[test]
fn read_budget_exhaustion_still_verifies_later_tracked_prefixes() {
    let dir = tempdir("traffic-read-budget");
    let log = dir.join("logs/access.json");
    std::fs::create_dir_all(log.parent().unwrap()).unwrap();
    let tracked = record_with("alice", json!(1), json!(2), &[("padding", json!("A".repeat(100)))]);
    let rewritten = record_with("alice", json!(1), json!(2), &[("padding", json!("B".repeat(100)))]);
    assert_eq!(tracked.len(), rewritten.len());
    std::fs::write(&log, &tracked).unwrap();
    let traffic =
        open(&log, &dir.join("traffic.sqlite3"), &["alice"], Options { max_verify_bytes: 1024, ..small(299, 300) });
    assert_eq!(traffic.collect().unwrap(), 1);
    std::fs::write(&log, &rewritten).unwrap();
    let rotated = log.with_file_name("access-2026-08-14T15-00-00.000-size.json");
    let first = record(3, 4).trim_end_matches('\n').to_string();
    std::fs::write(&rotated, first.clone() + &" ".repeat(299 - first.len()) + "\n").unwrap();
    assert_eq!(std::fs::metadata(&rotated).unwrap().len(), 300);
    assert!(runtime_message(traffic.collect().unwrap_err()).contains("rename-only"));
    assert_eq!(traffic.health().unwrap()["ready"], false);
    assert_eq!(total(&traffic), 10);
}

#[test]
fn strict_filtering_rejects_unknown_sentinels_bad_schema_and_oversize() {
    let dir = tempdir("traffic-strict");
    let (traffic, log) = collector(&dir);
    let d = |n: i64| json!(n);
    let lines = [
        record_with("mallory", d(12345), d(12345), &[]),
        record_with("invalidbase64:secret", d(12345), d(12345), &[]),
        record_with("invalid:secret", d(12345), d(12345), &[]),
        record_with("invalidformat:c2VjcmV0", d(12345), d(12345), &[]),
        record_with("invalid::", d(12345), d(12345), &[]),
        record_with("alice", d(12345), d(12345), &[("status", json!(407))]),
        record_with("alice", d(12345), d(12345), &[("request", json!({"method": "GET"}))]),
        record_with("alice", json!(true), d(12345), &[]),
        record_with("alice", d(12345), d(-1), &[]),
        json!({"request": {"method": "CONNECT"}, "status": 200, "user_id": "alice", "bytes_read": 1}).to_string()
            + "\n",
        "not-json\n".to_string(),
        "x".repeat(traffic.options.max_line_bytes as usize + 1) + "\n",
        record(2, 3),
    ];
    std::fs::write(&log, lines.concat()).unwrap();
    assert_eq!(traffic.collect().unwrap(), 1);
    assert_eq!(
        traffic.list_traffic().unwrap()["aggregate"],
        json!({"upload_bytes": 2, "download_bytes": 3, "total_bytes": 5,
               "upload_bytes_decimal": "2", "download_bytes_decimal": "3", "total_bytes_decimal": "5"})
    );
}

#[test]
fn managed_invaliduser_counts_while_exact_redaction_sentinel_is_rejected() {
    let dir = tempdir("traffic-sentinel");
    let log = dir.join("logs/access.json");
    std::fs::create_dir_all(log.parent().unwrap()).unwrap();
    std::fs::write(
        &log,
        record_with("invaliduser", json!(5), json!(7), &[]) + &record_with("invalid", json!(1), json!(1), &[]),
    )
    .unwrap();
    let traffic = open(&log, &dir.join("traffic.sqlite3"), &["invaliduser", "invalid"], Options::default());
    assert_eq!(traffic.collect().unwrap(), 1);
    assert_eq!(traffic.list_traffic().unwrap()["users"][0]["username"], "invaliduser");
    assert_eq!(total(&traffic), 12);
}

#[test]
fn reset_changes_only_local_baseline_and_is_transactional() {
    let dir = tempdir("traffic-reset");
    let (traffic, log) = collector(&dir);
    std::fs::write(&log, record(10, 20)).unwrap();
    traffic.collect().unwrap();
    let before = traffic.list_traffic().unwrap()["users"][0]["period_start"].as_str().unwrap().to_string();
    let reset = traffic.reset("alice").unwrap();
    assert_eq!((reset["username"].clone(), reset["total_bytes"].clone()), (json!("alice"), json!(0)));
    assert!(reset["period_start"].as_str().unwrap() >= before.as_str());
    append(&log, &record(1, 2));
    traffic.collect().unwrap();
    assert_eq!(traffic.list_traffic().unwrap()["users"][0]["total_bytes"], 3);
    assert!(matches!(traffic.reset("unknown"), Err(Error::Key(_))));
}

#[test]
fn missing_active_log_and_unsafe_files_fail_health() {
    let dir = tempdir("traffic-health");
    let (traffic, log) = collector(&dir);
    assert_eq!(traffic.health().unwrap()["ready"], true);
    std::fs::remove_file(&log).unwrap();
    assert_eq!(traffic.health().unwrap()["ready"], false);
    assert!(traffic.collect().unwrap_err().is_runtime());
    let target = dir.join("target");
    std::fs::write(&target, "").unwrap();
    std::os::unix::fs::symlink(&target, &log).unwrap();
    assert_eq!(traffic.health().unwrap()["ready"], false);
    assert!(traffic.collect().unwrap_err().is_runtime());
}

#[test]
fn database_and_wal_are_private_and_database_symlinks_are_rejected() {
    let dir = tempdir("traffic-private-db");
    let (traffic, _log) = collector(&dir);
    let database = dir.join("traffic.sqlite3");
    assert_eq!(crate::tests::mode_of(&database), 0o600);
    for suffix in ["-wal", "-shm"] {
        let sidecar = PathBuf::from(format!("{}{suffix}", database.display()));
        if sidecar.exists() {
            assert_eq!(crate::tests::mode_of(&sidecar), 0o600);
        }
    }
    traffic.close();
    let unsafe_log = dir.join("other/access.json");
    std::fs::create_dir_all(unsafe_log.parent().unwrap()).unwrap();
    std::fs::write(&unsafe_log, "").unwrap();
    std::fs::write(dir.join("database-target"), "").unwrap();
    let unsafe_database = dir.join("unsafe.sqlite3");
    std::os::unix::fs::symlink(dir.join("database-target"), &unsafe_database).unwrap();
    let err =
        TrafficCollector::new(&unsafe_log, &unsafe_database, users(&["alice"]), Options::default()).err().unwrap();
    assert!(runtime_message(err).contains("database is unsafe"));
}

#[test]
fn log_and_database_parent_symlinks_are_rejected() {
    let dir = tempdir("traffic-parent-symlinks");
    std::fs::create_dir_all(dir.join("real-logs")).unwrap();
    std::fs::write(dir.join("real-logs/access.json"), "").unwrap();
    std::os::unix::fs::symlink(dir.join("real-logs"), dir.join("linked-logs")).unwrap();
    let err = TrafficCollector::new(
        &dir.join("linked-logs/access.json"),
        &dir.join("traffic.sqlite3"),
        users(&["alice"]),
        Options::default(),
    )
    .err()
    .unwrap();
    assert!(runtime_message(err).contains("unsafe"));
    std::fs::create_dir_all(dir.join("safe-logs")).unwrap();
    std::fs::write(dir.join("safe-logs/access.json"), "").unwrap();
    std::fs::create_dir_all(dir.join("real-data")).unwrap();
    std::os::unix::fs::symlink(dir.join("real-data"), dir.join("linked-data")).unwrap();
    let err = TrafficCollector::new(
        &dir.join("safe-logs/access.json"),
        &dir.join("linked-data/traffic.sqlite3"),
        users(&["alice"]),
        Options::default(),
    )
    .err()
    .unwrap();
    assert!(runtime_message(err).contains("unsafe"));
}

#[test]
fn counter_overflow_is_quarantined_without_wrapping_or_replay() {
    let dir = tempdir("traffic-overflow");
    let (traffic, log) = collector(&dir);
    std::fs::write(&log, record(i64::MAX, 0)).unwrap();
    assert_eq!(traffic.collect().unwrap(), 1);
    append(&log, &record(0, 1));
    assert_eq!(traffic.collect().unwrap(), 0);
    assert_eq!(traffic.collect().unwrap(), 0);
    assert_eq!(total(&traffic), i64::MAX);
}

#[test]
fn contract_is_secret_free_and_documents_accounting_limits() {
    let dir = tempdir("traffic-contract");
    let (traffic, log) = collector(&dir);
    std::fs::write(&log, record(12345, 12345)).unwrap();
    traffic.collect().unwrap();
    let body = traffic.list_traffic().unwrap();
    assert_eq!((body["source"].clone(), body["unit"].clone()), (json!("caddy_connect_access_log"), json!("bytes")));
    assert_eq!(body["directions"], json!({"upload_bytes": "client_to_proxy", "download_bytes": "proxy_to_client"}));
    for key in [
        "closed_connect_tunnels_only",
        "active_tunnels_appear_on_close",
        "crash_can_lose_active_tunnel",
        "completed_records_survive_restart",
        "excludes_tls_ip_overhead",
        "reset_is_local_baseline_only",
    ] {
        assert_eq!(body["semantics"][key], true, "{key}");
    }
    assert!(!body.to_string().to_lowercase().contains("password"));
}

#[test]
fn rotation_candidates_are_bounded_before_collection() {
    let dir = tempdir("traffic-bounded");
    let log = dir.join("logs/access.json");
    std::fs::create_dir_all(log.parent().unwrap()).unwrap();
    std::fs::write(&log, "").unwrap();
    for index in 0..3 {
        std::fs::write(log.with_file_name(format!("access-2026-08-14T15-00-0{index}.000-size.json")), record(1, 1))
            .unwrap();
    }
    let traffic =
        open(&log, &dir.join("traffic.sqlite3"), &["alice"], Options { max_rotations: 2, ..Default::default() });
    assert!(runtime_message(traffic.collect().unwrap_err()).contains("rotation limit"));
}

fn count(db: &Path, sql: &str) -> i64 {
    Connection::open(db).unwrap().query_row(sql, [], |row| row.get(0)).unwrap()
}

#[test]
fn safely_consumed_deleted_rotation_state_is_pruned() {
    let dir = tempdir("traffic-pruned");
    let (traffic, log) = collector(&dir);
    std::fs::write(&log, record(1, 2)).unwrap();
    traffic.collect().unwrap();
    let rotated = log.with_file_name("access-2026-08-14T15-00-00.000-size.json");
    std::fs::rename(&log, &rotated).unwrap();
    std::fs::write(&log, record(3, 4)).unwrap();
    traffic.collect().unwrap();
    std::fs::remove_file(&rotated).unwrap();
    traffic.collect().unwrap();
    assert_eq!(count(&dir.join("traffic.sqlite3"), "SELECT COUNT(*) FROM traffic_files"), 1);
}

#[test]
fn deleted_partially_consumed_rotation_is_tombstoned_as_persistent_accounting_loss() {
    let dir = tempdir("traffic-loss");
    let (traffic, log) = collector(&dir);
    let rotated = log.with_file_name("access-2026-08-14T15-00-00.000-size.json");
    std::fs::write(&rotated, record(1, 2) + record(3, 4).trim_end_matches('\n')).unwrap();
    assert_eq!(traffic.collect().unwrap(), 1);
    std::fs::remove_file(&rotated).unwrap();
    assert!(runtime_message(traffic.collect().unwrap_err()).contains("accounting loss"));
    assert_eq!(traffic.health().unwrap()["ready"], false);
    let outcomes: [Result<()>; 3] =
        [traffic.list_traffic().map(drop), traffic.reset("alice").map(drop), traffic.archive_user("alice")];
    for outcome in outcomes {
        assert!(runtime_message(outcome.unwrap_err()).contains("accounting loss"));
    }
    let db = dir.join("traffic.sqlite3");
    assert_eq!(count(&db, "SELECT COUNT(*) FROM traffic_files"), 1);
    let error: String = Connection::open(&db)
        .unwrap()
        .query_row("SELECT error FROM accounting_state WHERE singleton=1", [], |row| row.get(0))
        .unwrap();
    assert_eq!(error, "accounting_loss");
}

#[test]
fn archiving_deleted_user_removes_live_counter_without_losing_history() {
    let dir = tempdir("traffic-archive");
    let (traffic, log) = collector(&dir);
    std::fs::write(&log, record(11, 13)).unwrap();
    assert_eq!(traffic.collect().unwrap(), 1);
    traffic.archive_user("alice").unwrap();
    assert_eq!(traffic.list_traffic().unwrap()["users"], json!([]));
    let row: (String, i64, i64) = Connection::open(dir.join("traffic.sqlite3"))
        .unwrap()
        .query_row("SELECT username,upload_bytes,download_bytes FROM traffic_archives", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    assert_eq!(row, ("alice".to_string(), 11, 13));
}

#[test]
fn aggregate_counter_never_exceeds_signed_sqlite_integer() {
    let dir = tempdir("traffic-aggregate");
    let (traffic, log) = collector(&dir);
    std::fs::write(&log, record(i64::MAX - 1, 0)).unwrap();
    assert_eq!(traffic.collect().unwrap(), 1);
    append(&log, &record_with("bob", json!(2), json!(0), &[]));
    assert_eq!(traffic.collect().unwrap(), 0);
    assert_eq!(total(&traffic), i64::MAX - 1);
}

#[test]
fn counter_contract_includes_exact_decimal_strings() {
    let dir = tempdir("traffic-decimal");
    let (traffic, log) = collector(&dir);
    std::fs::write(&log, record((1 << 53) + 1, 2)).unwrap();
    traffic.collect().unwrap();
    let body = traffic.list_traffic().unwrap();
    assert_eq!(body["users"][0]["upload_bytes_decimal"], "9007199254740993");
    assert_eq!(body["users"][0]["total_bytes_decimal"], "9007199254740995");
    assert_eq!(body["aggregate"]["total_bytes_decimal"], "9007199254740995");
}

// ---------------------------------------------------------------------- Python compatibility

fn schema_of(db: &Path) -> String {
    let database = Connection::open(db).unwrap();
    let mut statement = database.prepare("SELECT sql FROM sqlite_master ORDER BY name").unwrap();
    let rows = statement.query_map([], |row| row.get::<_, Option<String>>(0)).unwrap();
    rows.filter_map(|r| r.unwrap()).collect::<Vec<_>>().join("\n;\n")
}

/// The access log the Python collector consumed when it wrote the fixture database.
fn python_log() -> String {
    let line = |user: &str, up: i64, down: i64| {
        pc_common::json::dumps(
            &json!({"request": {"method": "CONNECT"}, "status": 200, "user_id": user, "bytes_read": up, "size": down}),
            &crate::pyjson::COMPACT,
        ) + "\n"
    };
    line("alice", 10, 20) + &line("bob", 1, 2) + &line("carol", 5, 5) + "partial"
}

#[test]
fn database_written_by_the_python_collector_is_read_and_continued() {
    // traffic.sqlite3 written by naive_manager.traffic in python:3.13.5: alice 10/20, bob reset
    // to 0/0, carol archived, the log consumed up to its unfinished last line.
    let dir = tempdir("traffic-python-db");
    let log = dir.join("logs/access.json");
    std::fs::create_dir_all(log.parent().unwrap()).unwrap();
    std::fs::write(&log, python_log()).unwrap();
    let db = dir.join("traffic.sqlite3");
    std::fs::write(&db, include_bytes!("testdata/python-traffic.db")).unwrap();
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
    // The fixture tracked the log by the identity it had on the machine that wrote it.
    let info = std::fs::metadata(&log).unwrap();
    Connection::open(&db)
        .unwrap()
        .execute(
            "UPDATE traffic_files SET device=?, inode=?, path=?",
            rusqlite::params![info.dev() as i64, info.ino() as i64, log.display().to_string()],
        )
        .unwrap();
    let expected: Value = serde_json::from_str(include_str!("testdata/python-traffic-rows.json")).unwrap();
    let traffic = open(&log, &db, &["alice", "bob", "carol"], Options::default());
    let listed = traffic.list_traffic().unwrap();
    let users = listed["users"].as_array().unwrap();
    assert_eq!(users.len(), 2);
    for (row, want) in users.iter().zip(expected["counters"].as_array().unwrap()) {
        assert_eq!(row["username"], want[0]);
        assert_eq!(row["upload_bytes"], want[1]);
        assert_eq!(row["download_bytes"], want[2]);
        assert_eq!(row["period_start"], want[3]);
        assert_eq!(row["updated_at"], want[4]);
    }
    // The prefix digest the Python collector stored verifies here: nothing is counted twice,
    // and the unfinished line is still waiting.
    assert_eq!(listed["pending"], true);
    assert_eq!(traffic.collect().unwrap(), 0);
    append(&log, &format!("\n{}", record(1, 1)));
    assert_eq!(traffic.collect().unwrap(), 1);
    assert_eq!(total(&traffic), 32);
    traffic.archive_user("alice").unwrap();
    traffic.close();
    let archived = count(&db, "SELECT COUNT(*) FROM traffic_archives");
    assert_eq!(archived, 2);
    // The schema text SQLite keeps is the Python collector's, byte for byte.
    assert_eq!(schema_of(&db), include_str!("testdata/python-schema.txt"));
    let fresh = dir.join("fresh.sqlite3");
    open(&log, &fresh, &[], Options::default()).close();
    assert_eq!(schema_of(&fresh), include_str!("testdata/python-schema.txt"));
}

#[test]
fn legacy_database_gains_the_columns_the_python_collector_added() {
    let dir = tempdir("traffic-legacy-db");
    let log = dir.join("access.json");
    std::fs::write(&log, "").unwrap();
    let db = dir.join("legacy.sqlite3");
    std::fs::write(&db, include_bytes!("testdata/legacy.db")).unwrap();
    open(&log, &db, &[], Options::default()).close();
    assert_eq!(schema_of(&db), include_str!("testdata/legacy-migrated-schema.txt"));
    let journal: String =
        Connection::open(&db).unwrap().query_row("PRAGMA journal_mode", [], |row| row.get(0)).unwrap();
    assert_eq!(journal, "wal");
}
