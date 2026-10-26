//! The manager's behaviour, ported from `tests/test_naive_manager.py`: fake Caddy hooks that
//! count reloads and probes and can fail on demand, fault seams for crashes at every journal
//! phase, and the HTTP API over a real Unix socket.

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use pc_common::{ServerOptions, UdsServer};
use serde_json::{json, Map, Value};

use crate::caddyfile::{self, ACCOUNTING_BEGIN, ACCOUNTING_END};
use crate::error::{Error, Result};
use crate::pyutil::{splitlines, strip};
use crate::service::{Hooks, NaiveManager, Settings};
use crate::traffic::{self, TrafficCollector};

pub const CADDY: &str = "{
    admin 127.0.0.1:2019
}
:4443 {
    bind 127.0.0.1
    route {
        forward_proxy {
            basic_auth old-user old-password
            basic_auth second second-password
            hide_ip
            hide_via
            upstream socks5://127.0.0.1:40000
        }
        file_server { root /var/www/naive }
    }
}
";

pub fn tempdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("naive-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// How the fake adapter reports a Caddyfile.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum Adapter {
    /// One handler with the USERS block's credentials (`Hooks.validate`).
    #[default]
    Users,
    /// Also the egress block's upstream and ACL (`EgressHooks.validate`).
    Egress,
    /// One handler per `forward_proxy` block (`LaneHooks.validate`).
    Lanes,
}

pub type Override = Box<dyn Fn() -> Result<()> + Send>;

pub struct HookState {
    pub adapter: Adapter,
    pub validated: Vec<String>,
    pub reloads: u32,
    pub probes: u32,
    pub fail_reload_calls: HashSet<u32>,
    pub fail_probe_times: u32,
    pub caddyfile: Option<PathBuf>,
    pub reload_snapshots: Vec<String>,
    pub adapted_config: Option<Value>,
    pub reload_override: Option<Override>,
    pub probe_override: Option<Override>,
    pub reachable: bool,
    pub readback_override: Option<Map<String, Value>>,
    pub greetings: Vec<(String, bool)>,
}

impl Default for HookState {
    fn default() -> Self {
        Self {
            adapter: Adapter::Users,
            validated: Vec::new(),
            reloads: 0,
            probes: 0,
            fail_reload_calls: HashSet::new(),
            fail_probe_times: 0,
            caddyfile: None,
            reload_snapshots: Vec::new(),
            adapted_config: None,
            reload_override: None,
            probe_override: None,
            reachable: true,
            readback_override: None,
            greetings: Vec::new(),
        }
    }
}

#[derive(Clone, Default)]
pub struct TestHooks(pub Arc<Mutex<HookState>>);

/// `re.findall(r"forward_proxy \{(.*?)\n\s*\}", text, re.DOTALL)`.
fn forward_proxy_blocks(text: &str) -> Vec<&str> {
    let mut blocks = Vec::new();
    let mut from = 0;
    while let Some(found) = text[from..].find("forward_proxy {") {
        let body_start = from + found + "forward_proxy {".len();
        let mut end = None;
        for (offset, _) in text[body_start..].match_indices('\n') {
            let after = &text[body_start + offset..];
            let trimmed = after.trim_start_matches(crate::pyutil::is_space);
            if trimmed.starts_with('}') {
                end = Some((body_start + offset, body_start + offset + (after.len() - trimmed.len()) + 1));
                break;
            }
        }
        let Some((body_end, match_end)) = end else { break };
        blocks.push(&text[body_start..body_end]);
        from = match_end;
    }
    blocks
}

impl TestHooks {
    pub fn new(adapter: Adapter) -> Self {
        let hooks = Self::default();
        hooks.get().adapter = adapter;
        hooks
    }

    pub fn get(&self) -> std::sync::MutexGuard<'_, HookState> {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn validate(&self, path: &Path) -> Result<Value> {
        let text = std::fs::read_to_string(path)?;
        let mut state = self.get();
        state.validated.push(text.clone());
        if let Some(config) = &state.adapted_config {
            return Ok(config.clone());
        }
        match state.adapter {
            Adapter::Users => {
                let count = caddyfile::managed_credentials(&text)?.len();
                Ok(json!({"apps": {"http": {"handler": "forward_proxy", "auth_credentials": vec!["opaque"; count]}}}))
            }
            Adapter::Egress => {
                let count = caddyfile::managed_credentials(&text)?.len();
                let parsed = crate::egress::parse(&text)?;
                let mut handler = json!({"handler": "forward_proxy", "auth_credentials": vec!["opaque"; count]});
                if let Some(upstream) = parsed.upstream {
                    handler["upstream"] = json!(upstream);
                }
                if !parsed.acl_deny.is_empty() {
                    handler["acl"] = json!([{"subjects": parsed.acl_deny}]);
                }
                if let Some(extra) = &state.readback_override {
                    for (key, value) in extra {
                        handler[key] = value.clone();
                    }
                }
                Ok(json!({"apps": {"http": handler}}))
            }
            Adapter::Lanes => {
                let mut handlers = Vec::new();
                for block in forward_proxy_blocks(&text) {
                    let lines = splitlines(block);
                    let count = lines.iter().filter(|l| crate::text::basic_auth_pair(l).is_some()).count();
                    let mut handler = json!({"handler": "forward_proxy", "auth_credentials": vec!["opaque"; count]});
                    if let Some(upstream) = lines.iter().find_map(|l| {
                        let rest = crate::pyutil::lstrip(l).strip_prefix("upstream")?;
                        rest.starts_with(crate::pyutil::is_space).then(|| crate::pyutil::split_whitespace(rest)[0])
                    }) {
                        handler["upstream"] = json!(upstream);
                    }
                    let deny: Vec<String> = lines
                        .iter()
                        .filter_map(|l| crate::text::deny_subjects(l))
                        .flatten()
                        .map(String::from)
                        .collect();
                    if !deny.is_empty() {
                        handler["acl"] = json!([{"subjects": deny}]);
                    }
                    if let Some(extra) = &state.readback_override {
                        for (key, value) in extra {
                            handler[key] = value.clone();
                        }
                    }
                    handlers.push(handler);
                }
                Ok(json!({"apps": {"http": {"routes": [{"handle": handlers}]}}}))
            }
        }
    }

    fn reload(&self) -> Result<()> {
        let mut state = self.get();
        if let Some(action) = &state.reload_override {
            return action();
        }
        state.reloads += 1;
        if let Some(path) = state.caddyfile.clone() {
            state.reload_snapshots.push(std::fs::read_to_string(path).unwrap_or_default());
        }
        if state.fail_reload_calls.contains(&state.reloads) {
            return Err(Error::runtime("reload failed"));
        }
        Ok(())
    }

    fn probe(&self) -> Result<()> {
        let mut state = self.get();
        if let Some(action) = &state.probe_override {
            return action();
        }
        state.probes += 1;
        if state.fail_probe_times > 0 {
            state.fail_probe_times -= 1;
            return Err(Error::runtime("probe failed"));
        }
        Ok(())
    }

    pub fn hooks(&self) -> Hooks {
        let (a, b, c, d) = (self.clone(), self.clone(), self.clone(), self.clone());
        Hooks {
            validate: Box::new(move |path| a.validate(path)),
            reload: Box::new(move || b.reload()),
            probe: Box::new(move || c.probe()),
            reachability: Box::new(move |url, _timeout, auth| {
                let mut state = d.get();
                state.greetings.push((url.to_string(), auth));
                Ok(state.reachable)
            }),
        }
    }

    pub fn reloads(&self) -> u32 {
        self.get().reloads
    }

    pub fn probes(&self) -> u32 {
        self.get().probes
    }
}

pub fn settings(dir: &Path) -> Settings {
    Settings::new(dir.join("Caddyfile"), dir.join("state").join("users.json"), dir.join("backups"), "naive.example.com")
}

pub fn manager_with(dir: &Path, hooks: &TestHooks, settings: Settings) -> Arc<NaiveManager> {
    if !settings.caddyfile.exists() {
        std::fs::write(&settings.caddyfile, CADDY).unwrap();
    }
    hooks.get().caddyfile = Some(settings.caddyfile.clone());
    let _ = dir;
    Arc::new(NaiveManager::new(settings, hooks.hooks()))
}

/// `manager(tmp_path, hooks)`: the sample Caddyfile, state and backups under `dir`.
pub fn manager(dir: &Path, hooks: &TestHooks) -> Arc<NaiveManager> {
    manager_with(dir, hooks, settings(dir))
}

pub fn bootstrapped(dir: &Path) -> Arc<NaiveManager> {
    let service = manager(dir, &TestHooks::default());
    service.bootstrap().unwrap();
    service
}

/// A collector whose managed users are the manager's own (`service.managed_usernames`).
pub fn attach(service: &Arc<NaiveManager>, log: &Path, db: &Path, options: traffic::Options) -> Arc<TrafficCollector> {
    let weak = Arc::downgrade(service);
    let collector = Arc::new(
        TrafficCollector::new(log, db, Box::new(move || weak.upgrade().unwrap().managed_usernames()), options).unwrap(),
    );
    service.set_traffic(Some(collector.clone()));
    collector
}

pub fn connect_line(user: &str, upload: i64, download: i64) -> String {
    format!(
        "{}\n",
        json!({"request": {"method": "CONNECT"}, "status": 200, "user_id": user, "bytes_read": upload, "size": download})
    )
}

pub fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

pub fn bytes(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

pub fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn state_json(service: &NaiveManager) -> Value {
    serde_json::from_slice(&bytes(&service.settings.state_file)).unwrap()
}

fn write_state(service: &NaiveManager, state: &Value) {
    std::fs::write(&service.settings.state_file, crate::state::encode_state(state)).unwrap();
}

fn transaction_path(service: &NaiveManager) -> PathBuf {
    service.transaction_file()
}

fn list(service: &NaiveManager) -> Vec<Value> {
    service.list_users().unwrap().as_array().unwrap().clone()
}

fn usernames(service: &NaiveManager) -> Vec<String> {
    list(service).iter().map(|row| row["username"].as_str().unwrap().to_string()).collect()
}

fn backups(service: &NaiveManager, suffix: &str) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(&service.settings.backup_dir)
        .map(|entries| entries.filter_map(|e| e.ok()).map(|e| e.path()).collect())
        .unwrap_or_default();
    found.retain(|p| p.to_string_lossy().ends_with(suffix));
    found.sort();
    found
}

fn first_backup(service: &NaiveManager, suffix: &str) -> String {
    backups(service, suffix)[0].file_name().unwrap().to_string_lossy().into_owned()
}

fn without_accounting(text: &str) -> String {
    let lines = splitlines(text);
    let begin = lines.iter().position(|l| strip(l) == ACCOUNTING_BEGIN).unwrap();
    let end = lines.iter().position(|l| strip(l) == ACCOUNTING_END).unwrap();
    let kept: Vec<&str> = lines[..begin].iter().chain(&lines[end + 1..]).copied().collect();
    kept.join("\n") + "\n"
}

fn conflict_message(err: Error) -> String {
    assert!(err.is_conflict(), "{err:?}");
    err.message().to_string()
}

fn user_row(name: &str, enabled: bool, reason: Value) -> Value {
    json!({"username": name, "enabled": enabled, "quota_bytes": null, "disabled_reason": reason, "lane": null})
}

/// `threading.Event`.
#[derive(Clone, Default)]
pub struct Event(Arc<(Mutex<bool>, Condvar)>);

impl Event {
    pub fn set(&self) {
        *self.0 .0.lock().unwrap() = true;
        self.0 .1.notify_all();
    }

    pub fn wait(&self, seconds: f64) -> bool {
        let guard = self.0 .0.lock().unwrap();
        let (guard, _) = self.0 .1.wait_timeout_while(guard, Duration::from_secs_f64(seconds), |set| !*set).unwrap();
        *guard
    }
}

// ---------------------------------------------------------------------- bootstrap

#[test]
fn bootstrap_imports_existing_credentials_without_changing_them() {
    let dir = tempdir("bootstrap-import");
    let service = manager(&dir, &TestHooks::default());
    service.bootstrap().unwrap();
    assert_eq!(list(&service), [user_row("old-user", true, Value::Null), user_row("second", true, Value::Null)]);
    assert_eq!(service.reveal("old-user").unwrap()["proxy_url"], "https://old-user:old-password@naive.example.com");
    let rendered = read(&service.settings.caddyfile);
    assert!(rendered.contains("# BEGIN NAIVE-MANAGER USERS"));
    assert!(rendered.contains("basic_auth old-user old-password"));
    assert!(rendered.contains("upstream socks5://127.0.0.1:40000"));
    assert_eq!(mode_of(&service.settings.caddyfile), 0o640);
    assert_eq!(mode_of(&service.settings.state_file), 0o600);
    assert_eq!(state_json(&service)["version"], 1);
    for needle in [
        "# BEGIN NAIVE-MANAGER ACCOUNTING",
        "output file /var/log/naive-proxy/access.json",
        "mode 0640",
        "roll_uncompressed",
        "roll_size 10MiB",
        "roll_keep 10",
        "request>headers>Proxy-Authorization delete",
        "wrap json",
        "user_id regexp ^(invalidbase64|invalidformat|invalid):.*$ invalid",
    ] {
        assert!(rendered.contains(needle), "{needle}");
    }
    assert!(!rendered.contains("sampling"));
    let accounting = rendered.split(ACCOUNTING_BEGIN).nth(1).unwrap().split(ACCOUNTING_END).next().unwrap();
    assert!(!accounting.contains("old-password"));
}

#[test]
fn create_rejects_exact_redaction_sentinel_without_mutation() {
    let dir = tempdir("sentinel-create");
    let service = bootstrapped(&dir);
    let (config, state) = (bytes(&service.settings.caddyfile), bytes(&service.settings.state_file));
    let before = backups(&service, "");
    let err = service.create(&json!("invalid"), &Value::Null, None, None).unwrap_err();
    assert_eq!(err, Error::value("reserved username"));
    assert_eq!(bytes(&service.settings.caddyfile), config);
    assert_eq!(bytes(&service.settings.state_file), state);
    assert_eq!(backups(&service, ""), before);
    assert_eq!(service.create(&json!("invaliduser"), &Value::Null, None, None).unwrap()["username"], "invaliduser");
}

#[test]
fn bootstrap_rejects_reserved_sentinel_import_before_mutation() {
    let dir = tempdir("sentinel-import");
    let caddy = dir.join("Caddyfile");
    std::fs::write(&caddy, CADDY.replace("basic_auth old-user old-password", "basic_auth invalid password")).unwrap();
    let service = manager(&dir, &TestHooks::default());
    let before = bytes(&caddy);
    assert!(conflict_message(service.bootstrap().unwrap_err()).contains("reserved accounting username"));
    assert_eq!(bytes(&caddy), before);
    assert!(!service.settings.state_file.exists() && !service.settings.backup_dir.exists());
}

#[test]
fn bootstrap_rejects_preexisting_managed_markers() {
    let dir = tempdir("preexisting-markers");
    std::fs::write(
        dir.join("Caddyfile"),
        CADDY.replace(
            "            basic_auth old-user old-password",
            "            # BEGIN NAIVE-MANAGER USERS\n            basic_auth old-user old-password\n            # END NAIVE-MANAGER USERS",
        ),
    )
    .unwrap();
    let service = manager(&dir, &TestHooks::default());
    assert!(conflict_message(service.bootstrap().unwrap_err()).contains("managed credential markers already present"));
    assert!(!service.settings.state_file.exists());
}

#[test]
fn bootstrap_rejects_caddyfile_reached_through_symlinked_parent() {
    let dir = tempdir("symlinked-parent");
    std::fs::create_dir_all(dir.join("real-config")).unwrap();
    std::fs::write(dir.join("real-config/Caddyfile"), CADDY).unwrap();
    std::os::unix::fs::symlink(dir.join("real-config"), dir.join("linked-config")).unwrap();
    let hooks = TestHooks::default();
    let mut settings = settings(&dir);
    settings.caddyfile = dir.join("linked-config/Caddyfile");
    let service = manager_with(&dir, &hooks, settings);
    assert!(conflict_message(service.bootstrap().unwrap_err()).contains("unsafe"));
}

#[test]
fn bootstrap_fails_closed_on_reserved_sentinel_in_existing_state() {
    for accounting_present in [true, false] {
        let dir = tempdir(&format!("sentinel-state-{accounting_present}"));
        let hooks = TestHooks::default();
        let service = manager(&dir, &hooks);
        service.bootstrap().unwrap();
        let mut state = state_json(&service);
        state["users"][0]["username"] = json!("invalid");
        write_state(&service, &state);
        let mut rendered = read(&service.settings.caddyfile)
            .replace("basic_auth old-user old-password", "basic_auth invalid old-password");
        if !accounting_present {
            rendered = without_accounting(&rendered);
        }
        std::fs::write(&service.settings.caddyfile, &rendered).unwrap();
        let (config, state) = (bytes(&service.settings.caddyfile), bytes(&service.settings.state_file));
        let err = manager(&dir, &hooks).bootstrap().unwrap_err();
        assert!(conflict_message(err).contains("reserved accounting username in manager state"));
        assert_eq!(bytes(&service.settings.caddyfile), config);
        assert_eq!(bytes(&service.settings.state_file), state);
        assert!(!transaction_path(&service).exists());
    }
}

#[test]
fn bootstrap_transactionally_migrates_existing_managed_state_to_accounting() {
    let dir = tempdir("migrate-accounting");
    let hooks = TestHooks::default();
    let service = manager(&dir, &hooks);
    service.bootstrap().unwrap();
    std::fs::write(&service.settings.caddyfile, without_accounting(&read(&service.settings.caddyfile))).unwrap();
    {
        let mut state = hooks.get();
        state.reloads = 0;
        state.probes = 0;
    }
    service.bootstrap().unwrap();
    assert_eq!(read(&service.settings.caddyfile).matches(ACCOUNTING_BEGIN).count(), 1);
    assert_eq!((hooks.reloads(), hooks.probes()), (1, 1));
    assert!(!transaction_path(&service).exists());
    let count = backups(&service, ".Caddyfile").len();
    service.bootstrap().unwrap();
    assert_eq!(backups(&service, ".Caddyfile").len(), count);
    assert_eq!(hooks.reloads(), 1);
}

#[test]
fn accounting_migration_fault_at_each_phase_restores_then_retries_idempotently() {
    for fault_phase in ["prepared", "files_replaced", "rollback_pending"] {
        let dir = tempdir(&format!("migration-fault-{fault_phase}"));
        let hooks = TestHooks::default();
        let service = manager(&dir, &hooks);
        service.bootstrap().unwrap();
        std::fs::write(&service.settings.caddyfile, without_accounting(&read(&service.settings.caddyfile))).unwrap();
        let old_state = bytes(&service.settings.state_file);
        let injected = Arc::new(AtomicBool::new(false));
        let flag = injected.clone();
        service.fs.faults.lock().unwrap().after_transaction = Some(Box::new(move |transaction| {
            if transaction["phase"] == fault_phase && !flag.swap(true, Ordering::SeqCst) {
                return Err(Error::Other(format!("simulated crash at {fault_phase}")));
            }
            Ok(())
        }));
        let err = service.bootstrap().unwrap_err();
        assert!(err.message().contains("simulated crash"), "{err:?}");
        let recovered = manager(&dir, &hooks);
        recovered.bootstrap().unwrap();
        assert!(injected.load(Ordering::SeqCst));
        assert_eq!(bytes(&recovered.settings.state_file), old_state);
        assert_eq!(read(&recovered.settings.caddyfile).matches(ACCOUNTING_BEGIN).count(), 1);
        assert!(!transaction_path(&recovered).exists());
        recovered.bootstrap().unwrap();
        assert_eq!(read(&recovered.settings.caddyfile).matches(ACCOUNTING_BEGIN).count(), 1);
    }
}

fn crash_on(path: PathBuf) -> crate::fsops::PathHook {
    Box::new(move |written| {
        if written == path {
            return Err(Error::Other("simulated crash between initial file writes".into()));
        }
        Ok(())
    })
}

#[test]
fn bootstrap_recovers_after_crash_between_initial_config_and_state_writes() {
    let dir = tempdir("crash-initial");
    let hooks = TestHooks::default();
    let service = manager(&dir, &hooks);
    service.fs.faults.lock().unwrap().before_write = Some(crash_on(service.settings.state_file.clone()));
    assert!(service.bootstrap().unwrap_err().message().contains("simulated crash"));
    let recovered = manager(&dir, &hooks);
    recovered.bootstrap().unwrap();
    assert_eq!(read(&recovered.settings.caddyfile).matches("# BEGIN NAIVE-MANAGER USERS").count(), 1);
    assert_eq!(list(&recovered), [user_row("old-user", true, Value::Null), user_row("second", true, Value::Null)]);
    assert!(!transaction_path(&recovered).exists());
}

#[test]
fn bootstrap_recovery_remembers_initial_import_after_recovery_crash() {
    let dir = tempdir("crash-recovery");
    let hooks = TestHooks::default();
    let service = manager(&dir, &hooks);
    service.fs.faults.lock().unwrap().before_write = Some(crash_on(service.settings.state_file.clone()));
    assert!(service.bootstrap().is_err());
    let failing = manager(&dir, &hooks);
    let failed = Arc::new(AtomicBool::new(false));
    let (flag, caddyfile) = (failed.clone(), failing.settings.caddyfile.clone());
    failing.fs.faults.lock().unwrap().before_write = Some(Box::new(move |path| {
        if path == caddyfile && !flag.swap(true, Ordering::SeqCst) {
            return Err(Error::Os("recovery interrupted".into()));
        }
        Ok(())
    }));
    assert_eq!(failing.bootstrap().unwrap_err(), Error::recovery("transaction recovery failed"));
    let transaction = transaction_path(&service);
    assert_eq!(serde_json::from_str::<Value>(&read(&transaction)).unwrap()["phase"], "recovery_failed");
    let recovered = manager(&dir, &hooks);
    recovered.bootstrap().unwrap();
    assert_eq!(read(&recovered.settings.caddyfile).matches("# BEGIN NAIVE-MANAGER USERS").count(), 1);
    assert_eq!(list(&recovered).len(), 2);
    assert!(!transaction.exists());
}

// ---------------------------------------------------------------------- transactions

#[test]
fn create_disable_enable_rotate_and_delete_are_transactional() {
    let dir = tempdir("lifecycle");
    let hooks = TestHooks::default();
    let service = manager(&dir, &hooks);
    service.bootstrap().unwrap();
    let created = service.create(&json!("phone"), &Value::Null, None, None).unwrap();
    assert!(created["proxy_url"].as_str().unwrap().starts_with("https://phone:"));
    assert!(read(&service.settings.caddyfile).contains("basic_auth phone "));
    service.set_enabled("phone", false).unwrap();
    assert!(!read(&service.settings.caddyfile).contains("basic_auth phone "));
    assert_eq!(list(&service).last().unwrap(), &user_row("phone", false, json!("manual")));
    service.set_enabled("phone", true).unwrap();
    let before = service.reveal("phone").unwrap()["proxy_url"].clone();
    service.rotate("phone", None, None).unwrap();
    assert_ne!(service.reveal("phone").unwrap()["proxy_url"], before);
    let log = dir.join("access.json");
    std::fs::write(&log, "").unwrap();
    attach(&service, &log, &dir.join("traffic.sqlite3"), traffic::Options::default());
    service.delete("phone").unwrap();
    assert!(!usernames(&service).contains(&"phone".to_string()));
    assert_eq!((hooks.reloads(), hooks.probes()), (5, 5));
}

#[test]
fn successful_mutation_persists_paired_backups_and_clears_journal() {
    let dir = tempdir("paired-backups");
    let service = bootstrapped(&dir);
    let (configs, states) = (backups(&service, ".Caddyfile").len(), backups(&service, ".users.json").len());
    service.create(&json!("phone"), &Value::Null, None, None).unwrap();
    assert_eq!(backups(&service, ".Caddyfile").len(), configs + 1);
    assert_eq!(backups(&service, ".users.json").len(), states + 1);
    assert!(!transaction_path(&service).exists());
}

#[test]
fn live_reload_occurs_only_after_journal_requires_backup_restore() {
    let dir = tempdir("reload-after-journal");
    let hooks = TestHooks::default();
    let service = manager(&dir, &hooks);
    service.bootstrap().unwrap();
    let phases = Arc::new(Mutex::new(Vec::new()));
    let (seen, transaction) = (phases.clone(), transaction_path(&service));
    hooks.get().reload_override = Some(Box::new(move || {
        let journal: Value = serde_json::from_str(&std::fs::read_to_string(&transaction).unwrap()).unwrap();
        seen.lock().unwrap().push(journal["phase"].as_str().unwrap().to_string());
        Ok(())
    }));
    service.create(&json!("phone"), &Value::Null, None, None).unwrap();
    assert_eq!(*phases.lock().unwrap(), ["rollback_pending"]);
}

fn identity(path: &Path) -> (u64, u64) {
    let info = std::fs::metadata(path).unwrap();
    (info.dev(), info.ino())
}

#[test]
fn validated_caddyfile_replace_fsyncs_its_own_parent_directory() {
    let dir = tempdir("fsync-parent");
    std::fs::create_dir_all(dir.join("config")).unwrap();
    let hooks = TestHooks::default();
    let mut settings = settings(&dir);
    settings.caddyfile = dir.join("config/Caddyfile");
    std::fs::write(&settings.caddyfile, CADDY).unwrap();
    let service = manager_with(&dir, &hooks, settings);
    service.bootstrap().unwrap();
    let synced = Arc::new(Mutex::new(HashSet::new()));
    let record = synced.clone();
    service.fs.faults.lock().unwrap().synced_directory = Some(Box::new(move |path| {
        record.lock().unwrap().insert(identity(path));
    }));
    service.create(&json!("phone"), &Value::Null, None, None).unwrap();
    assert!(synced.lock().unwrap().contains(&identity(&dir.join("config"))));
}

#[test]
fn initial_backup_directory_is_durable_before_live_config_replace() {
    let dir = tempdir("durable-backups");
    let service = manager(&dir, &TestHooks::default());
    let synced = Arc::new(Mutex::new(HashSet::new()));
    let violations = Arc::new(Mutex::new(0));
    let record = synced.clone();
    let (seen, bad, caddyfile, parent) =
        (synced.clone(), violations.clone(), service.settings.caddyfile.clone(), dir.clone());
    {
        let mut faults = service.fs.faults.lock().unwrap();
        faults.synced_directory = Some(Box::new(move |path| {
            record.lock().unwrap().insert(identity(path));
        }));
        faults.replaced = Some(Box::new(move |destination| {
            if destination == caddyfile && !seen.lock().unwrap().contains(&identity(&parent)) {
                *bad.lock().unwrap() += 1;
            }
        }));
    }
    service.bootstrap().unwrap();
    assert_eq!(*violations.lock().unwrap(), 0);
}

#[test]
fn failed_reload_restores_config_and_state() {
    let dir = tempdir("failed-reload");
    let hooks = TestHooks::default();
    let service = manager(&dir, &hooks);
    service.bootstrap().unwrap();
    let (config, state) = (bytes(&service.settings.caddyfile), bytes(&service.settings.state_file));
    hooks.get().fail_reload_calls = [1].into();
    let err = service.create(&json!("must-rollback"), &Value::Null, None, None).unwrap_err();
    assert_eq!(err, Error::runtime("reload failed"));
    assert_eq!(bytes(&service.settings.caddyfile), config);
    assert_eq!(bytes(&service.settings.state_file), state);
    assert!(!read(&service.settings.caddyfile).contains("must-rollback"));
}

#[test]
fn probe_failure_reloads_and_probes_restored_live_configuration() {
    let dir = tempdir("failed-probe");
    let hooks = TestHooks::default();
    let service = manager(&dir, &hooks);
    service.bootstrap().unwrap();
    let (config, state) = (bytes(&service.settings.caddyfile), bytes(&service.settings.state_file));
    hooks.get().fail_probe_times = 1;
    let err = service.create(&json!("must-rollback"), &Value::Null, None, None).unwrap_err();
    assert_eq!(err, Error::runtime("probe failed"));
    assert_eq!(bytes(&service.settings.caddyfile), config);
    assert_eq!(bytes(&service.settings.state_file), state);
    let state = hooks.get();
    assert_eq!(state.reload_snapshots.len(), 2);
    assert!(state.reload_snapshots[0].contains("must-rollback"));
    assert_eq!(state.reload_snapshots[1].as_bytes(), config.as_slice());
    assert_eq!(state.probes, 2);
}

#[test]
fn failed_rollback_is_reported_and_manager_stays_unhealthy() {
    let dir = tempdir("failed-rollback");
    let hooks = TestHooks::default();
    let service = manager(&dir, &hooks);
    service.bootstrap().unwrap();
    {
        let mut state = hooks.get();
        state.fail_probe_times = 1;
        state.fail_reload_calls = [2].into();
    }
    let err = service.create(&json!("ambiguous-live-state"), &Value::Null, None, None).unwrap_err();
    assert_eq!(err, Error::recovery("rollback failed; manager requires recovery"));
    assert_eq!(service.health()["ready"], false);
    assert!(transaction_path(&service).exists());
    assert!(service
        .create(&json!("must-not-run"), &Value::Null, None, None)
        .unwrap_err()
        .message()
        .contains("recovery"));
    hooks.get().fail_reload_calls.clear();
    let recovered = manager(&dir, &hooks);
    recovered.bootstrap().unwrap();
    assert_eq!(recovered.health()["ready"], true);
    assert!(!transaction_path(&service).exists());
}

#[test]
fn rollback_file_restore_failure_persists_recovery_failed_journal() {
    let dir = tempdir("restore-failure");
    let hooks = TestHooks::default();
    let service = manager(&dir, &hooks);
    service.bootstrap().unwrap();
    hooks.get().fail_probe_times = 1;
    let failed = Arc::new(AtomicBool::new(false));
    let (flag, caddyfile) = (failed.clone(), service.settings.caddyfile.clone());
    service.fs.faults.lock().unwrap().before_write = Some(Box::new(move |path| {
        if path == caddyfile && !flag.swap(true, Ordering::SeqCst) {
            return Err(Error::Os("restore write failed".into()));
        }
        Ok(())
    }));
    let err = service.create(&json!("restore-failure"), &Value::Null, None, None).unwrap_err();
    assert_eq!(err, Error::recovery("rollback failed; manager requires recovery"));
    let journal: Value = serde_json::from_str(&read(&transaction_path(&service))).unwrap();
    assert_eq!(journal["phase"], "recovery_failed");
    assert_eq!(service.health()["ready"], false);
    assert!(service
        .create(&json!("must-not-run"), &Value::Null, None, None)
        .unwrap_err()
        .message()
        .contains("recovery"));
}

fn write_journal(service: &NaiveManager, journal: Value) {
    std::fs::write(transaction_path(service), journal.to_string()).unwrap();
}

#[test]
fn bootstrap_recovers_prepared_transaction_from_both_backups() {
    let dir = tempdir("recover-prepared");
    let hooks = TestHooks::default();
    let service = manager(&dir, &hooks);
    service.bootstrap().unwrap();
    let (config, state) = (bytes(&service.settings.caddyfile), bytes(&service.settings.state_file));
    std::fs::create_dir_all(&service.settings.backup_dir).unwrap();
    std::fs::write(service.settings.backup_dir.join("crash.Caddyfile"), &config).unwrap();
    std::fs::write(service.settings.backup_dir.join("crash.users.json"), &state).unwrap();
    std::fs::write(
        &service.settings.caddyfile,
        read(&service.settings.caddyfile).replace("old-password", "partial-change"),
    )
    .unwrap();
    let mut changed = state_json(&service);
    changed["users"][0]["password"] = json!("partial-change");
    std::fs::write(&service.settings.state_file, changed.to_string()).unwrap();
    write_journal(
        &service,
        json!({"version": 1, "phase": "prepared", "config_backup": "crash.Caddyfile", "state_backup": "crash.users.json"}),
    );
    let recovered = manager(&dir, &hooks);
    recovered.bootstrap().unwrap();
    assert_eq!(bytes(&recovered.settings.caddyfile), config);
    assert_eq!(bytes(&recovered.settings.state_file), state);
    assert!(!transaction_path(&service).exists());
    assert_eq!(hooks.get().reload_snapshots.last().unwrap().as_bytes(), config.as_slice());
    assert_eq!(hooks.probes(), 1);
}

#[test]
fn failed_startup_recovery_durably_marks_journal_recovery_failed() {
    let dir = tempdir("recover-missing");
    let hooks = TestHooks::default();
    let service = manager(&dir, &hooks);
    service.bootstrap().unwrap();
    write_journal(
        &service,
        json!({"version": 1, "phase": "prepared", "config_backup": "missing.Caddyfile", "state_backup": "missing.users.json"}),
    );
    let recovered = manager(&dir, &hooks);
    assert_eq!(recovered.bootstrap().unwrap_err(), Error::recovery("transaction recovery failed"));
    let journal: Value = serde_json::from_str(&read(&transaction_path(&service))).unwrap();
    assert_eq!(journal["phase"], "recovery_failed");
    assert_eq!(recovered.health()["ready"], false);
}

#[test]
fn bootstrap_commits_files_replaced_transaction_by_reloading_current_files() {
    let dir = tempdir("recover-files-replaced");
    let hooks = TestHooks::default();
    let service = manager(&dir, &hooks);
    service.bootstrap().unwrap();
    let (config, state_before) = (bytes(&service.settings.caddyfile), bytes(&service.settings.state_file));
    let mut state = state_json(&service);
    state["users"].as_array_mut().unwrap().push(json!({
        "username": "crash-commit", "password": "new-password", "enabled": true,
        "created_at": "now", "updated_at": "now",
    }));
    let rendered = caddyfile::render_managed(&read(&service.settings.caddyfile), &state).unwrap();
    std::fs::write(&service.settings.caddyfile, rendered).unwrap();
    write_state(&service, &state);
    std::fs::create_dir_all(&service.settings.backup_dir).unwrap();
    std::fs::write(service.settings.backup_dir.join("commit.Caddyfile"), &config).unwrap();
    std::fs::write(service.settings.backup_dir.join("commit.users.json"), &state_before).unwrap();
    write_journal(
        &service,
        json!({"version": 1, "phase": "files_replaced", "config_backup": "commit.Caddyfile", "state_backup": "commit.users.json"}),
    );
    let recovered = manager(&dir, &hooks);
    recovered.bootstrap().unwrap();
    assert_eq!(list(&recovered).last().unwrap(), &user_row("crash-commit", true, Value::Null));
    assert!(read(&recovered.settings.caddyfile).contains("basic_auth crash-commit new-password"));
    assert!(!transaction_path(&service).exists());
    assert!(hooks.get().reload_snapshots.last().unwrap().contains("crash-commit"));
    assert_eq!(hooks.probes(), 1);
}

#[test]
fn bootstrap_falls_back_to_backups_if_files_replaced_generation_is_incomplete() {
    let dir = tempdir("recover-incomplete");
    let hooks = TestHooks::default();
    let service = manager(&dir, &hooks);
    service.bootstrap().unwrap();
    let (config, state) = (bytes(&service.settings.caddyfile), bytes(&service.settings.state_file));
    std::fs::create_dir_all(&service.settings.backup_dir).unwrap();
    std::fs::write(service.settings.backup_dir.join("partial.Caddyfile"), &config).unwrap();
    std::fs::write(service.settings.backup_dir.join("partial.users.json"), &state).unwrap();
    std::fs::write(
        &service.settings.caddyfile,
        read(&service.settings.caddyfile).replace("old-password", "partial-new"),
    )
    .unwrap();
    write_journal(
        &service,
        json!({"version": 1, "phase": "files_replaced", "config_backup": "partial.Caddyfile", "state_backup": "partial.users.json"}),
    );
    let recovered = manager(&dir, &hooks);
    recovered.bootstrap().unwrap();
    assert_eq!(bytes(&recovered.settings.caddyfile), config);
    assert_eq!(bytes(&recovered.settings.state_file), state);
    assert!(!transaction_path(&service).exists());
    assert_eq!(hooks.get().reload_snapshots.last().unwrap().as_bytes(), config.as_slice());
}

// ---------------------------------------------------------------------- drift and health

#[test]
fn out_of_band_managed_block_edit_is_rejected() {
    let dir = tempdir("out-of-band");
    let service = bootstrapped(&dir);
    std::fs::write(
        &service.settings.caddyfile,
        read(&service.settings.caddyfile).replace("old-password", "changed-outside"),
    )
    .unwrap();
    assert!(service.create(&json!("phone"), &Value::Null, None, None).unwrap_err().is_conflict());
}

fn append_and_check_unready(name: &str, edit: impl Fn(String) -> String) {
    let dir = tempdir(name);
    let service = bootstrapped(&dir);
    std::fs::write(&service.settings.caddyfile, edit(read(&service.settings.caddyfile))).unwrap();
    assert_eq!(service.health()["ready"], false, "{name}");
}

#[test]
fn additional_basic_auth_outside_managed_block_makes_health_unready() {
    append_and_check_unready("rogue-auth", |text| {
        text.replace(
            "            # END NAIVE-MANAGER USERS",
            "            # END NAIVE-MANAGER USERS\n            basic_auth rogue rogue-password",
        )
    });
}

#[test]
fn multiple_forward_proxy_blocks_make_health_unready() {
    append_and_check_unready("two-forward", |text| {
        text + "\n:4555 {\n    forward_proxy {\n        hide_ip\n    }\n}\n"
    });
}

#[test]
fn blockless_forward_proxy_directive_makes_health_unready() {
    append_and_check_unready("blockless-forward", |text| text + "\n:4555 {\n    forward_proxy\n}\n");
}

#[test]
fn global_basic_auth_outside_managed_block_makes_health_unready() {
    append_and_check_unready("global-auth", |text| {
        text + "\n:4666 {\n    basic_auth {\n        rogue JDJhJDE0JHJvZ3Vl\n    }\n    respond 200\n}\n"
    });
}

#[test]
fn adapted_semantic_drift_makes_health_unready() {
    let cases = [
        json!({"routes": [{"handler": "forward_proxy", "auth_credentials": ["one", "two"]},
                          {"handler": "forward_proxy", "auth_credentials": []}]}),
        json!({"routes": [{"handler": "forward_proxy", "auth_credentials": ["one", "two"]},
                          {"handler": "authentication", "providers": {"http_basic": {}}}]}),
        json!({"routes": [{"handler": "forward_proxy", "auth_credentials": ["extra"]}]}),
    ];
    for (index, adapted) in cases.into_iter().enumerate() {
        let dir = tempdir(&format!("semantic-drift-{index}"));
        let hooks = TestHooks::default();
        let service = manager(&dir, &hooks);
        service.bootstrap().unwrap();
        hooks.get().adapted_config = Some(adapted);
        assert_eq!(service.health()["ready"], false);
    }
}

#[test]
fn health_fails_closed_while_transaction_journal_exists() {
    let dir = tempdir("journal-exists");
    let service = bootstrapped(&dir);
    std::fs::write(transaction_path(&service), "{}").unwrap();
    assert_eq!(service.health()["ready"], false);
}

// ---------------------------------------------------------------------- journal validation

fn journal_case(name: &str, build: impl Fn(&str, &str) -> Value) -> (Arc<NaiveManager>, PathBuf) {
    let dir = tempdir(name);
    let service = bootstrapped(&dir);
    let (config, state) = (first_backup(&service, ".Caddyfile"), first_backup(&service, ".users.json"));
    write_journal(&service, build(&config, &state));
    (service, dir)
}

fn assert_invalid_journal(result: Result<impl std::fmt::Debug>) {
    assert_eq!(result.unwrap_err(), Error::recovery("invalid transaction journal"));
}

#[test]
fn invalid_recovery_origin_is_rejected() {
    let (_service, dir) = journal_case(
        "journal-origin",
        |config, state| json!({"version": 1, "phase": "recovery_failed", "recovery_from": "unknown_phase", "config_backup": config, "state_backup": state}),
    );
    assert_invalid_journal(manager(&dir, &TestHooks::default()).bootstrap());
}

#[test]
fn unknown_transaction_field_is_rejected() {
    let (_service, dir) = journal_case(
        "journal-field",
        |config, state| json!({"version": 1, "phase": "prepared", "config_backup": config, "state_backup": state, "unexpected": "field"}),
    );
    assert_invalid_journal(manager(&dir, &TestHooks::default()).bootstrap());
}

#[test]
fn transaction_root_and_version_types_are_strict() {
    let (service, _) = journal_case("journal-root", |_, _| json!([]));
    assert_invalid_journal(service.read_transaction());
    let (service, _) = journal_case(
        "journal-version",
        |config, state| json!({"version": true, "phase": "prepared", "config_backup": config, "state_backup": state}),
    );
    assert_invalid_journal(service.read_transaction());
}

#[test]
fn backup_names_must_be_a_matching_typed_pair() {
    let (service, _) = journal_case(
        "journal-pair",
        |config, state| json!({"version": 1, "phase": "prepared", "config_backup": state, "state_backup": config}),
    );
    assert_invalid_journal(service.read_transaction());
}

#[test]
fn recovery_origin_is_rejected_outside_recovery_failed_phase() {
    let (_service, dir) = journal_case(
        "journal-origin-phase",
        |config, state| json!({"version": 1, "phase": "prepared", "recovery_from": "files_replaced", "config_backup": config, "state_backup": state}),
    );
    assert_invalid_journal(manager(&dir, &TestHooks::default()).bootstrap());
}

#[test]
fn non_boolean_state_existence_marker_is_rejected() {
    let (_service, dir) = journal_case(
        "journal-marker-type",
        |config, state| json!({"version": 1, "phase": "bootstrap_prepared", "state_existed": "false", "config_backup": config, "state_backup": state}),
    );
    assert_invalid_journal(manager(&dir, &TestHooks::default()).bootstrap());
}

#[test]
fn bootstrap_journal_requires_explicit_absent_state_marker() {
    let (_service, dir) = journal_case(
        "journal-marker-missing",
        |config, state| json!({"version": 1, "phase": "bootstrap_prepared", "config_backup": config, "state_backup": state}),
    );
    assert_invalid_journal(manager(&dir, &TestHooks::default()).bootstrap());
}

// ---------------------------------------------------------------------- HTTP

pub struct Api {
    pub socket: PathBuf,
    handle: pc_common::ShutdownHandle,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Api {
    fn drop(&mut self) {
        self.handle.shutdown();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// `ManagerHTTPServer(socket_path, service, token)` serving on its own thread.
pub fn serve(service: &Arc<NaiveManager>, dir: &Path, token: &str) -> Api {
    let socket = dir.join("manager.sock");
    let mut options = ServerOptions::new(&socket);
    options.mode = 0o600;
    options.max_body = crate::server::MAX_BODY;
    let server = UdsServer::bind(options).unwrap();
    let handle = server.shutdown_handle();
    let handler = crate::server::handler(service.clone(), token.to_string());
    let thread = std::thread::spawn(move || server.serve(handler));
    Api { socket, handle, thread: Some(thread) }
}

pub fn call(api: &Api, method: &str, path: &str, body: Option<Value>, token: Option<&str>) -> (u16, String) {
    let headers: Vec<(&str, &str)> = token.map(|t| vec![("X-Naive-Token", t)]).unwrap_or_default();
    let raw = body.map(|b| b.to_string().into_bytes());
    let reply =
        pc_common::client::request(&api.socket, method, path, &headers, raw.as_deref(), Duration::from_secs(10))
            .unwrap();
    (reply.status, String::from_utf8(reply.body).unwrap())
}

pub fn parse(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

const TOKEN: &str = "internal-token";

#[test]
fn unix_api_requires_token_and_never_lists_passwords() {
    let dir = tempdir("api-token");
    let service = bootstrapped(&dir);
    let api = serve(&service, &dir, TOKEN);
    let (status, body) = call(&api, "GET", "/v1/users", None, None);
    assert_eq!((status, parse(&body)), (401, json!({"detail": "unauthorized"})));
    let (status, body) = call(&api, "GET", "/v1/users", None, Some(TOKEN));
    assert_eq!(status, 200);
    assert_eq!(parse(&body), json!([user_row("old-user", true, Value::Null), user_row("second", true, Value::Null)]));
    assert!(!body.contains("old-password"));
    assert_eq!(mode_of(&api.socket), 0o600);
}

#[test]
fn unix_api_persists_and_removes_naive_quota_without_exposing_credentials() {
    let dir = tempdir("api-quota");
    let service = bootstrapped(&dir);
    let api = serve(&service, &dir, TOKEN);
    let (status, body) =
        call(&api, "POST", "/v1/users/old-user/quota", Some(json!({"quota_bytes": 4096})), Some(TOKEN));
    assert_eq!(status, 200);
    assert_eq!(
        parse(&body),
        json!({"username": "old-user", "quota_bytes": 4096, "enabled": true, "disabled_reason": null})
    );
    let (status, listed) = call(&api, "GET", "/v1/users", None, Some(TOKEN));
    assert_eq!((status, parse(&listed)[0]["quota_bytes"].clone()), (200, json!(4096)));
    assert!(!listed.contains("old-password"));
    let (status, body) =
        call(&api, "POST", "/v1/users/old-user/quota", Some(json!({"quota_bytes": null})), Some(TOKEN));
    assert_eq!(status, 200);
    assert_eq!(
        parse(&body),
        json!({"username": "old-user", "quota_bytes": null, "enabled": true, "disabled_reason": null})
    );
    assert_eq!(list(&service)[0]["quota_bytes"], Value::Null);
    // Refusals keep the Python handler's bodies.
    assert_eq!(call(&api, "POST", "/v1/users/old-user/quota", Some(json!({})), Some(TOKEN)).0, 422);
    let (status, body) = call(&api, "POST", "/v1/users/nobody/quota", Some(json!({"quota_bytes": 1})), Some(TOKEN));
    assert_eq!((status, parse(&body)), (404, json!({"detail": "not found"})));
    let (status, body) = call(&api, "GET", "/v1/nope", None, Some(TOKEN));
    assert_eq!((status, parse(&body)), (404, json!({"detail": "not found"})));
    let (status, body) = call(&api, "POST", "/v1/users", Some(json!({"username": "bad name"})), Some(TOKEN));
    assert_eq!((status, parse(&body)), (422, json!({"detail": "invalid request"})));
    let (status, body) = call(&api, "POST", "/v1/users", Some(json!({"username": "second"})), Some(TOKEN));
    assert_eq!(
        (status, parse(&body)),
        (409, json!({"detail": "configuration conflict", "code": "configuration_conflict"}))
    );
    let (status, body) = call(&api, "POST", "/v1/users", Some(json!({"username": "laptop"})), Some(TOKEN));
    assert_eq!(status, 201);
    assert_eq!(parse(&body)["username"], "laptop");
    assert_eq!(call(&api, "PATCH", "/v1/users", None, Some(TOKEN)).0, 501);
}

#[test]
fn unix_health_returns_503_when_manager_is_not_ready() {
    let dir = tempdir("api-health");
    let hooks = TestHooks::default();
    let service = manager(&dir, &hooks);
    service.bootstrap().unwrap();
    hooks.get().probe_override = Some(Box::new(|| Err(Error::runtime("probe failed"))));
    let api = serve(&service, &dir, TOKEN);
    let (status, body) = call(&api, "GET", "/v1/health", None, Some(TOKEN));
    assert_eq!(status, 503);
    assert_eq!(parse(&body)["ready"], false);
}

#[test]
fn authenticated_traffic_api_lists_and_resets_without_changing_credentials() {
    let dir = tempdir("api-traffic");
    let service = bootstrapped(&dir);
    let log = dir.join("access.json");
    std::fs::write(&log, connect_line("old-user", 12, 34)).unwrap();
    attach(&service, &log, &dir.join("traffic.sqlite3"), traffic::Options::default());
    let before = service.reveal("old-user").unwrap()["proxy_url"].clone();
    let api = serve(&service, &dir, TOKEN);
    assert_eq!(call(&api, "GET", "/v1/traffic", None, None).0, 401);
    let (status, body) = call(&api, "GET", "/v1/traffic", None, Some(TOKEN));
    assert_eq!((status, parse(&body)["users"][0]["total_bytes"].clone()), (200, json!(46)));
    let (status, body) = call(&api, "POST", "/v1/users/old-user/traffic/reset", Some(json!({})), Some(TOKEN));
    assert_eq!((status, parse(&body)["total_bytes"].clone()), (200, json!(0)));
    assert_eq!(call(&api, "POST", "/v1/users/unknown/traffic/reset", Some(json!({})), Some(TOKEN)).0, 404);
    drop(api);
    assert_eq!(service.reveal("old-user").unwrap()["proxy_url"], before);
}

#[test]
fn healthcheck_probe_needs_a_200_with_the_token() {
    let dir = tempdir("api-probe");
    let hooks = TestHooks::default();
    let service = manager(&dir, &hooks);
    service.bootstrap().unwrap();
    let token = "t".repeat(40);
    let api = serve(&service, &dir, &token);
    let probe = |token: &str| {
        let reply = pc_common::client::request(
            &api.socket,
            "GET",
            "/v1/health",
            &[(crate::server::TOKEN_HEADER, token)],
            None,
            Duration::from_secs(3),
        )
        .unwrap();
        reply.status == 200
    };
    assert!(probe(&token));
    assert!(!probe(&"w".repeat(40)));
    hooks.get().probe_override = Some(Box::new(|| Err(Error::runtime("probe failed"))));
    assert!(!probe(&token));
}

// ---------------------------------------------------------------------- quotas and traffic

#[test]
fn health_reports_without_rewriting_config_for_an_exhausted_quota() {
    let dir = tempdir("health-quota");
    let hooks = TestHooks::default();
    let service = manager(&dir, &hooks);
    service.bootstrap().unwrap();
    service.set_quota("old-user", &json!(40)).unwrap();
    let log = dir.join("access.json");
    std::fs::write(&log, connect_line("old-user", 40, 60)).unwrap();
    attach(&service, &log, &dir.join("traffic.sqlite3"), traffic::Options::default());
    let config = bytes(&service.settings.caddyfile);
    let reloads = hooks.reloads();
    assert_eq!(service.health(), json!({"ready": true, "host": "naive.example.com"}));
    assert_eq!(bytes(&service.settings.caddyfile), config);
    assert_eq!(hooks.reloads(), reloads);
    assert_eq!(list(&service)[0]["enabled"], true);
    assert_eq!(service.enforce_quotas().unwrap(), ["old-user"]);
    assert_eq!(list(&service)[0]["enabled"], false);
}

#[test]
fn quota_reset_keeps_access_disabled_until_explicit_enable() {
    let dir = tempdir("quota-reset");
    let service = bootstrapped(&dir);
    service.set_quota("old-user", &json!(40)).unwrap();
    let log = dir.join("access.json");
    std::fs::write(&log, connect_line("old-user", 12, 34)).unwrap();
    attach(&service, &log, &dir.join("traffic.sqlite3"), traffic::Options::default());
    assert_eq!(service.enforce_quotas().unwrap(), ["old-user"]);
    assert_eq!(list(&service)[0]["disabled_reason"], "quota");
    service.reset_traffic("old-user").unwrap();
    assert_eq!(
        (list(&service)[0]["enabled"].clone(), list(&service)[0]["disabled_reason"].clone()),
        (json!(false), json!("quota"))
    );
    service.set_enabled("old-user", true).unwrap();
    assert_eq!(
        (list(&service)[0]["enabled"].clone(), list(&service)[0]["disabled_reason"].clone()),
        (json!(true), Value::Null)
    );
}

#[test]
fn health_and_traffic_report_do_not_deadlock_on_opposite_lock_timing() {
    let dir = tempdir("deadlock");
    let service = bootstrapped(&dir);
    let log = dir.join("access.json");
    std::fs::write(&log, "").unwrap();
    let (entered, release) = (Event::default(), Event::default());
    let (signal, gate, weak) = (entered.clone(), release.clone(), Arc::downgrade(&service));
    let collector = TrafficCollector::new(
        &log,
        &dir.join("traffic.sqlite3"),
        Box::new(move || {
            signal.set();
            assert!(gate.wait(1.0));
            weak.upgrade().unwrap().managed_usernames()
        }),
        traffic::Options::default(),
    )
    .unwrap();
    service.set_traffic(Some(Arc::new(collector)));
    let results = Arc::new(Mutex::new(HashMap::new()));
    let (reporter, sink) = (service.clone(), results.clone());
    let report = std::thread::spawn(move || {
        let report = reporter.traffic_report().is_ok();
        sink.lock().unwrap().insert("report", report);
    });
    assert!(entered.wait(1.0));
    let (checker, sink) = (service.clone(), results.clone());
    let health = std::thread::spawn(move || {
        checker.health();
        sink.lock().unwrap().insert("health", true);
    });
    release.set();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while (!report.is_finished() || !health.is_finished()) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(report.is_finished() && health.is_finished());
    assert_eq!(results.lock().unwrap().len(), 2);
}

fn backlog_options(drain_rounds: u32) -> traffic::Options {
    traffic::Options { max_line_bytes: 128, max_read_bytes: 160, max_drain_rounds: drain_rounds, ..Default::default() }
}

#[test]
fn reset_refuses_when_bounded_drain_cannot_finish_pre_reset_backlog() {
    let dir = tempdir("reset-backlog");
    let service = bootstrapped(&dir);
    let log = dir.join("access.json");
    std::fs::write(&log, connect_line("old-user", 1, 2).repeat(8)).unwrap();
    let traffic = attach(&service, &log, &dir.join("traffic.sqlite3"), backlog_options(2));
    assert!(conflict_message(service.reset_traffic("old-user").unwrap_err()).contains("backlog"));
    while traffic.list_traffic().unwrap()["pending"] == true {
        traffic.collect().unwrap();
    }
    assert_eq!(service.reset_traffic("old-user").unwrap()["total_bytes"], 0);
    assert_eq!(traffic.list_traffic().unwrap()["users"][0]["total_bytes"], 0);
}

#[test]
fn delete_refuses_pending_backlog_then_archives_and_tombstones_username() {
    let dir = tempdir("delete-backlog");
    let service = bootstrapped(&dir);
    let log = dir.join("access.json");
    std::fs::write(&log, connect_line("old-user", 1, 2).repeat(8)).unwrap();
    let traffic = attach(&service, &log, &dir.join("traffic.sqlite3"), backlog_options(1));
    assert!(conflict_message(service.delete("old-user").unwrap_err()).contains("backlog"));
    assert!(usernames(&service).contains(&"old-user".to_string()));
    while traffic.list_traffic().unwrap()["pending"] == true {
        traffic.collect().unwrap();
    }
    service.delete("old-user").unwrap();
    assert!(!usernames(&service).contains(&"old-user".to_string()));
    assert_eq!(traffic.list_traffic().unwrap()["users"], json!([]));
    let state = state_json(&service);
    assert_eq!(
        state["tombstones"],
        json!([{"username": "old-user", "deleted_at": state["tombstones"][0]["deleted_at"]}])
    );
    let err = service.create(&json!("old-user"), &Value::Null, None, None).unwrap_err();
    assert!(conflict_message(err).contains("retired"));
}

/// A collector whose first managed-users snapshot pauses until released.
fn paused_collector(service: &Arc<NaiveManager>, log: &Path, db: &Path) -> (Arc<TrafficCollector>, Event, Event) {
    let (taken, release) = (Event::default(), Event::default());
    let first = Arc::new(AtomicBool::new(true));
    let (signal, gate, weak) = (taken.clone(), release.clone(), Arc::downgrade(service));
    let collector = Arc::new(
        TrafficCollector::new(
            log,
            db,
            Box::new(move || {
                let users = weak.upgrade().unwrap().managed_usernames();
                if first.swap(false, Ordering::SeqCst) {
                    signal.set();
                    assert!(gate.wait(2.0));
                }
                users
            }),
            traffic::Options::default(),
        )
        .unwrap(),
    );
    service.set_traffic(Some(collector.clone()));
    (collector, taken, release)
}

#[test]
fn delete_serializes_with_collector_that_already_captured_old_user_snapshot() {
    let dir = tempdir("delete-serialize");
    let service = bootstrapped(&dir);
    let log = dir.join("access.json");
    std::fs::write(&log, "").unwrap();
    let db = dir.join("traffic.sqlite3");
    let (traffic, taken, release) = paused_collector(&service, &log, &db);
    let collector = traffic.clone();
    let collecting = std::thread::spawn(move || collector.collect().unwrap());
    assert!(taken.wait(1.0));
    let deleter = service.clone();
    let deleting = std::thread::spawn(move || deleter.delete("old-user").is_ok());
    std::thread::sleep(Duration::from_secs(1));
    assert!(!deleting.is_finished());
    std::fs::write(&log, connect_line("old-user", 1, 2)).unwrap();
    release.set();
    assert_eq!(collecting.join().unwrap(), 1);
    assert!(deleting.join().unwrap());
    assert_eq!(traffic.list_traffic().unwrap()["users"], json!([]));
    let database = rusqlite::Connection::open(&db).unwrap();
    let counters: i64 = database.query_row("SELECT COUNT(*) FROM traffic_counters", [], |r| r.get(0)).unwrap();
    assert_eq!(counters, 0);
    let archived: (String, i64, i64) = database
        .query_row("SELECT username,upload_bytes,download_bytes FROM traffic_archives", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    assert_eq!(archived, ("old-user".to_string(), 1, 2));
}

#[test]
fn quota_is_persisted_and_exhaustion_revokes_future_admission() {
    let dir = tempdir("quota-exhaustion");
    let service = bootstrapped(&dir);
    let log = dir.join("access.json");
    std::fs::write(&log, "").unwrap();
    attach(&service, &log, &dir.join("traffic.sqlite3"), traffic::Options::default());
    assert_eq!(
        service.set_quota("old-user", &json!(100)).unwrap(),
        json!({"username": "old-user", "quota_bytes": 100, "enabled": true, "disabled_reason": null})
    );
    assert_eq!(list(&service)[0]["quota_bytes"], 100);
    assert_eq!(state_json(&service)["users"][0]["quota_bytes"], 100);
    std::fs::write(&log, connect_line("old-user", 40, 60)).unwrap();
    assert_eq!(service.enforce_quotas().unwrap(), ["old-user"]);
    let row = &list(&service)[0];
    assert_eq!((row["enabled"].clone(), row["disabled_reason"].clone()), (json!(false), json!("quota")));
    assert!(!read(&service.settings.caddyfile).contains("basic_auth old-user old-password"));
    let err = service.set_enabled("old-user", true).unwrap_err();
    assert_eq!(err.code(), Some("quota_exhausted"));
    assert!(err.message().contains("quota"));
    service.set_quota("old-user", &Value::Null).unwrap();
    assert_eq!(list(&service)[0]["quota_bytes"], Value::Null);
    service.set_enabled("old-user", true).unwrap();
    assert_eq!(list(&service)[0]["enabled"], true);
}

#[test]
fn quota_rejects_non_positive_boolean_or_overflow_values_without_mutation() {
    for (index, value) in [json!(0), json!(-1), json!(true), json!(9223372036854775808u64)].into_iter().enumerate() {
        let dir = tempdir(&format!("quota-invalid-{index}"));
        let service = bootstrapped(&dir);
        let before = bytes(&service.settings.state_file);
        let err = service.set_quota("old-user", &value).unwrap_err();
        assert!(matches!(&err, Error::Value(m) if m.contains("quota")), "{value}: {err:?}");
        assert_eq!(bytes(&service.settings.state_file), before);
    }
}

#[test]
fn legacy_user_state_defaults_to_unlimited_quota() {
    let dir = tempdir("legacy-quota");
    let service = bootstrapped(&dir);
    let mut state = state_json(&service);
    for row in state["users"].as_array_mut().unwrap() {
        let row = row.as_object_mut().unwrap();
        row.shift_remove("quota_bytes");
        row.shift_remove("disabled_reason");
    }
    write_state(&service, &state);
    assert!(list(&service).iter().all(|row| row["quota_bytes"].is_null()));
    service.create(&json!("legacy-compatible"), &Value::Null, None, None).unwrap();
    let created = list(&service).into_iter().find(|row| row["username"] == "legacy-compatible").unwrap();
    assert_eq!(created["quota_bytes"], Value::Null);
}

#[test]
fn create_serializes_with_collector_snapshot_before_new_user_record() {
    let dir = tempdir("create-serialize");
    let service = bootstrapped(&dir);
    let log = dir.join("access.json");
    std::fs::write(&log, "").unwrap();
    let (traffic, taken, release) = paused_collector(&service, &log, &dir.join("traffic.sqlite3"));
    let collector = traffic.clone();
    let collecting = std::thread::spawn(move || collector.collect().unwrap());
    assert!(taken.wait(1.0));
    let creator = service.clone();
    let creating = std::thread::spawn(move || creator.create(&json!("new-user"), &Value::Null, None, None).is_ok());
    std::thread::sleep(Duration::from_secs(1));
    assert!(!creating.is_finished());
    release.set();
    assert_eq!(collecting.join().unwrap(), 0);
    assert!(creating.join().unwrap());
    let mut appended = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
    std::io::Write::write_all(&mut appended, connect_line("new-user", 2, 3).as_bytes()).unwrap();
    assert_eq!(traffic.collect().unwrap(), 1);
    assert_eq!(traffic.collect().unwrap(), 0);
    assert_eq!(traffic.list_traffic().unwrap()["users"][0]["total_bytes"], 5);
}

#[test]
fn concurrent_create_and_collect_stress_completes_without_deadlock() {
    let dir = tempdir("stress");
    let service = bootstrapped(&dir);
    let log = dir.join("access.json");
    std::fs::write(&log, "").unwrap();
    let traffic = attach(&service, &log, &dir.join("traffic.sqlite3"), traffic::Options::default());
    let start = Arc::new(std::sync::Barrier::new(2));
    let failures = Arc::new(Mutex::new(Vec::new()));
    let (barrier, sink, collector) = (start.clone(), failures.clone(), traffic.clone());
    let collect = std::thread::spawn(move || {
        barrier.wait();
        for _ in 0..40 {
            if let Err(err) = collector.collect() {
                sink.lock().unwrap().push(err);
            }
        }
    });
    let (barrier, sink, creator, path) = (start.clone(), failures.clone(), service.clone(), log.clone());
    let create = std::thread::spawn(move || {
        barrier.wait();
        for index in 0..8 {
            let name = format!("stress-{index}");
            if let Err(err) = creator.create(&json!(name), &Value::Null, None, None) {
                sink.lock().unwrap().push(err);
            }
            let mut appended = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            std::io::Write::write_all(&mut appended, connect_line(&name, 1, 1).as_bytes()).unwrap();
        }
    });
    collect.join().unwrap();
    create.join().unwrap();
    assert!(failures.lock().unwrap().is_empty(), "{:?}", failures.lock().unwrap());
    while traffic.list_traffic().unwrap()["pending"] == true {
        traffic.collect().unwrap();
    }
    assert_eq!(traffic.list_traffic().unwrap()["aggregate"]["total_bytes"], 16);
}

#[test]
fn persistent_accounting_loss_surfaces_as_conflict_for_report_reset_and_delete() {
    let dir = tempdir("accounting-loss");
    let service = bootstrapped(&dir);
    let log = dir.join("access.json");
    std::fs::write(&log, "").unwrap();
    let traffic = attach(&service, &log, &dir.join("traffic.sqlite3"), traffic::Options::default());
    let rotated = dir.join("access-2026-08-14T15-00-00.000-size.json");
    std::fs::write(&rotated, connect_line("old-user", 1, 2) + "partial").unwrap();
    assert_eq!(traffic.collect().unwrap(), 1);
    std::fs::remove_file(&rotated).unwrap();
    assert!(traffic.collect().unwrap_err().message().contains("accounting loss"));
    for outcome in
        [service.traffic_report().map(drop), service.reset_traffic("old-user").map(drop), service.delete("old-user")]
    {
        assert!(conflict_message(outcome.unwrap_err()).contains("accounting"));
    }
    assert!(usernames(&service).contains(&"old-user".to_string()));
}

#[test]
fn password_rotation_preserves_accounting_history() {
    let dir = tempdir("rotation-history");
    let service = bootstrapped(&dir);
    let log = dir.join("access.json");
    std::fs::write(&log, connect_line("old-user", 5, 7)).unwrap();
    let traffic = attach(&service, &log, &dir.join("traffic.sqlite3"), traffic::Options::default());
    traffic.collect().unwrap();
    let created_at = state_json(&service)["users"][0]["created_at"].clone();
    service.rotate("old-user", None, None).unwrap();
    assert_eq!(traffic.list_traffic().unwrap()["users"][0]["total_bytes"], 12);
    assert_eq!(state_json(&service)["users"][0]["created_at"], created_at);
}

#[test]
fn exact_local_caddy_accepts_managed_accounting_config_when_forwardproxy_module_present() {
    let caddy = Path::new("/usr/local/bin/caddy");
    if !caddy.is_file() {
        eprintln!("exact local Caddy is absent");
        return;
    }
    let modules = std::process::Command::new(caddy).arg("list-modules").output().unwrap();
    if !String::from_utf8_lossy(&modules.stdout).lines().any(|l| l == "http.handlers.forward_proxy") {
        eprintln!("exact local Caddy lacks http.handlers.forward_proxy");
        return;
    }
    let dir = tempdir("local-caddy");
    let service = manager(&dir, &TestHooks::default());
    std::fs::write(
        &service.settings.caddyfile,
        read(&service.settings.caddyfile).replace(
            "file_server { root /var/www/naive }",
            "file_server {\n            root /var/www/naive\n        }",
        ),
    )
    .unwrap();
    service.bootstrap().unwrap();
    let result = std::process::Command::new(caddy)
        .args(["validate", "--config"])
        .arg(&service.settings.caddyfile)
        .output()
        .unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let version = std::process::Command::new(caddy).arg("version").output().unwrap();
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("v2.11.7 "));
}

// ---------------------------------------------------------------------- operation ids

#[test]
fn create_with_operation_id_replays_the_same_credential() {
    let dir = tempdir("op-replay");
    let service = bootstrapped(&dir);
    let first =
        service.create(&json!("phone"), &Value::Null, Some("caller-supplied-password-01"), Some("op-1")).unwrap();
    let second =
        service.create(&json!("phone"), &Value::Null, Some("caller-supplied-password-01"), Some("op-1")).unwrap();
    assert_eq!(first["proxy_url"], second["proxy_url"]);
    assert_eq!(second["replayed"], true);
    assert!(first.get("replayed").is_none());
    assert_eq!(usernames(&service), ["old-user", "second", "phone"]);
}

#[test]
fn operation_id_reused_for_another_username_conflicts() {
    let dir = tempdir("op-conflict");
    let service = bootstrapped(&dir);
    service.create(&json!("phone"), &Value::Null, Some("caller-supplied-password-01"), Some("op-1")).unwrap();
    let err =
        service.create(&json!("laptop"), &Value::Null, Some("caller-supplied-password-02"), Some("op-1")).unwrap_err();
    assert_eq!(err.code(), Some("operation_conflict"));
    assert!(err.message().contains("operation"));
    assert_eq!(usernames(&service), ["old-user", "second", "phone"]);
}

#[test]
fn caller_supplied_password_is_used_verbatim_and_validated() {
    let dir = tempdir("op-password");
    let service = bootstrapped(&dir);
    let revealed = service.create(&json!("phone"), &Value::Null, Some("caller-supplied-password-01"), None).unwrap();
    assert!(revealed["proxy_url"].as_str().unwrap().contains("caller-supplied-password-01"));
    for bad in ["short", "has spaces in it and is long"] {
        assert!(matches!(service.create(&json!("laptop"), &Value::Null, Some(bad), None), Err(Error::Value(_))));
    }
    assert_eq!(usernames(&service), ["old-user", "second", "phone"]);
}

#[test]
fn rotate_with_operation_id_is_replayable() {
    let dir = tempdir("op-rotate");
    let service = bootstrapped(&dir);
    service.create(&json!("phone"), &Value::Null, None, None).unwrap();
    let first = service.rotate("phone", Some("rotated-password-0123456"), Some("op-2")).unwrap();
    let second = service.rotate("phone", Some("rotated-password-0123456"), Some("op-2")).unwrap();
    assert_eq!(first["proxy_url"], second["proxy_url"]);
    assert_eq!(second["replayed"], true);
    assert!(first["proxy_url"].as_str().unwrap().contains("rotated-password-0123456"));
    let err = service.create(&json!("laptop"), &Value::Null, None, Some("op-2")).unwrap_err();
    assert!(conflict_message(err).contains("operation"));
}

#[test]
fn an_operation_record_is_written_with_the_state_it_describes() {
    let dir = tempdir("op-record");
    let service = bootstrapped(&dir);
    service.create(&json!("phone"), &Value::Null, Some("caller-supplied-password-01"), Some("op-1")).unwrap();
    let record = state_json(&service)["operations"]["op-1"].clone();
    assert_eq!((record["operation"].clone(), record["username"].clone()), (json!("create"), json!("phone")));
    assert!(record["result"]["proxy_url"].as_str().unwrap().contains("caller-supplied-password-01"));
}

#[test]
fn legacy_state_without_operations_map_is_upgraded_on_read() {
    let dir = tempdir("op-legacy");
    let service = bootstrapped(&dir);
    let mut state = service.read_state().unwrap();
    state.as_object_mut().unwrap().shift_remove("operations");
    service.apply(state).unwrap();
    assert_eq!(service.read_state().unwrap()["operations"], json!({}));
}

#[test]
fn operation_records_older_than_the_retention_window_are_pruned() {
    let dir = tempdir("op-prune");
    let service = bootstrapped(&dir);
    service.create(&json!("phone"), &Value::Null, Some("caller-supplied-password-01"), Some("op-1")).unwrap();
    let mut state = service.read_state().unwrap();
    state["operations"]["op-old"] = json!({
        "operation": "create", "username": "ghost",
        "completed_at": "2000-01-01T00:00:00+00:00", "result": {"username": "ghost"},
    });
    service.apply(state).unwrap();
    let kept: Vec<String> = service.read_state().unwrap()["operations"].as_object().unwrap().keys().cloned().collect();
    assert_eq!(kept, ["op-1"]);
}

// ---------------------------------------------------------------------- state compatibility

#[test]
fn state_written_by_the_python_manager_is_read() {
    // users.json and the Caddyfile written by the Python manager (python:3.13.5) after a
    // create with a quota and an operation id, a disable, a lane, an egress apply and a
    // delete; the operation's timestamp was moved forward so it is never pruned.
    let dir = tempdir("python-state");
    let python_state = include_str!("testdata/python-users.json");
    std::fs::create_dir_all(dir.join("state")).unwrap();
    std::fs::write(dir.join("Caddyfile"), include_str!("testdata/python-Caddyfile")).unwrap();
    std::fs::set_permissions(dir.join("Caddyfile"), std::fs::Permissions::from_mode(0o640)).unwrap();
    std::fs::write(dir.join("state/users.json"), python_state).unwrap();
    std::fs::set_permissions(dir.join("state/users.json"), std::fs::Permissions::from_mode(0o600)).unwrap();
    let credential = dir.join("xray-router-ingress");
    std::fs::write(&credential, format!("naive-a1b2c3d4:{}\n", "K".repeat(40))).unwrap();
    let hooks = TestHooks::new(Adapter::Lanes);
    let mut settings = settings(&dir);
    settings.provider_url = Some("socks5://127.0.0.1:45000".into());
    settings.router_url = Some("socks5://127.0.0.1:45101".into());
    settings.router_credential_file = Some(credential);
    let service = manager_with(&dir, &hooks, settings);
    // Read and written back in the Python layout, byte for byte.
    let state = service.read_state().unwrap();
    assert_eq!(String::from_utf8(crate::state::encode_state(&state)).unwrap(), python_state);
    service.bootstrap().unwrap();
    assert_eq!(read(&dir.join("state/users.json")), python_state);
    assert_eq!(hooks.reloads(), 0);
    assert_eq!(
        list(&service),
        [
            user_row("old-user", true, Value::Null),
            user_row("second", true, Value::Null),
            json!({"username": "phone", "enabled": true, "quota_bytes": 1000, "disabled_reason": null, "lane": "grant:7f3a"}),
        ]
    );
    let egress = service.egress().unwrap();
    assert_eq!((egress["managed"].clone(), egress["acl"].clone()), (json!(true), json!(["example.com", "10.0.0.0/8"])));
    assert_eq!(egress["current"]["operation_id"], "op-e1");
    assert_eq!(service.lanes().unwrap()["lanes"][0]["users"], json!(["phone"]));
    let replayed =
        service.create(&json!("phone"), &json!(1000), Some("caller-supplied-password-01"), Some("op-1")).unwrap();
    assert_eq!(replayed["replayed"], true);
    // A change keeps the key order the Python manager wrote.
    service.set_enabled("second", false).unwrap();
    let after = read(&dir.join("state/users.json"));
    let keys: Vec<String> = parse(&after).as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys, ["version", "host", "users", "tombstones", "lanes", "operations", "egress"]);
    assert!(after.contains("\"password\": \"sécond-password\""));
}
