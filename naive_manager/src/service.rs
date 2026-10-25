//! The manager core: users, quotas and traffic over the Caddyfile and `users.json`, every
//! change one journaled transaction (backup pair, write, reload, probe, restore on failure).
//!
//! Locking mirrors the Python manager: a re-entrant manager lock serialises state and file
//! work; lifecycle operations take the traffic collector's operation lock first, so a
//! collection pass never interleaves with a membership change.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::{json, Map, Value};

use crate::caddyfile::{self, ACCOUNTING_BEGIN, ACCOUNTING_END};
use crate::error::{Error, Result};
use crate::fsops::{assert_regular, exists, mkstemp, read_text, Fs};
use crate::pyutil::{backup_stamp, is_bare_name, now_iso, now_parts, quote, token_urlsafe, ReentrantMutex};
use crate::state;
use crate::traffic::TrafficCollector;

pub type Validate = Box<dyn Fn(&Path) -> Result<Value> + Send + Sync>;
pub type Action = Box<dyn Fn() -> Result<()> + Send + Sync>;
pub type Reachability = Box<dyn Fn(&str, f64, bool) -> Result<bool> + Send + Sync>;

/// Where the manager's files are and what this node offers.
#[derive(Debug, Clone)]
pub struct Settings {
    pub caddyfile: PathBuf,
    pub state_file: PathBuf,
    pub backup_dir: PathBuf,
    pub public_host: String,
    pub caddyfile_mode: u32,
    /// The host's WARP proxy-mode endpoint (`NAIVE_EGRESS_WARP`), the only address the egress
    /// API writes for the `warp` provider.
    pub provider_url: Option<String>,
    /// This service's ingress on the node's Xray-router (`NAIVE_EGRESS_ROUTER`) and the file
    /// holding its `user:password`; the credential never leaves the manager.
    pub router_url: Option<String>,
    pub router_credential_file: Option<PathBuf>,
}

impl Settings {
    pub fn new(caddyfile: PathBuf, state_file: PathBuf, backup_dir: PathBuf, public_host: &str) -> Self {
        Self {
            caddyfile,
            state_file,
            backup_dir,
            public_host: public_host.to_string(),
            caddyfile_mode: 0o640,
            provider_url: None,
            router_url: None,
            router_credential_file: None,
        }
    }
}

/// What the manager does to Caddy: adapt-and-validate a file, reload the running config,
/// probe the cover site, and greet an egress provider.
pub struct Hooks {
    pub validate: Validate,
    pub reload: Action,
    pub probe: Action,
    pub reachability: Reachability,
}

pub struct NaiveManager {
    pub settings: Settings,
    pub(crate) hooks: Hooks,
    pub fs: Fs,
    lock: ReentrantMutex,
    recovery_failed: AtomicBool,
    traffic: Mutex<Option<Arc<TrafficCollector>>>,
}

pub(crate) fn object(value: &Value) -> Result<&Map<String, Value>> {
    value.as_object().ok_or_else(|| Error::Other("object expected".into()))
}

pub(crate) fn object_mut(value: &mut Value) -> Result<&mut Map<String, Value>> {
    value.as_object_mut().ok_or_else(|| Error::Other("object expected".into()))
}

fn users_mut(state: &mut Value) -> Result<&mut Vec<Value>> {
    state.get_mut("users").and_then(Value::as_array_mut).ok_or_else(|| Error::Key("'users'".into()))
}

fn users(state: &Value) -> &[Value] {
    state.get("users").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}

fn find_mut<'a>(state: &'a mut Value, username: &str) -> Result<&'a mut Map<String, Value>> {
    users_mut(state)?
        .iter_mut()
        .filter_map(Value::as_object_mut)
        .find(|row| row.get("username").and_then(Value::as_str) == Some(username))
        .ok_or_else(|| Error::NotFound("user not found".into()))
}

fn find<'a>(state: &'a Value, username: &str) -> Result<&'a Map<String, Value>> {
    users(state)
        .iter()
        .filter_map(Value::as_object)
        .find(|row| row.get("username").and_then(Value::as_str) == Some(username))
        .ok_or_else(|| Error::NotFound("user not found".into()))
}

fn is_enabled(row: &Map<String, Value>) -> bool {
    matches!(row.get("enabled"), Some(Value::Bool(true)))
}

impl NaiveManager {
    pub fn new(settings: Settings, hooks: Hooks) -> Self {
        Self {
            settings,
            hooks,
            fs: Fs::default(),
            lock: ReentrantMutex::default(),
            recovery_failed: AtomicBool::new(false),
            traffic: Mutex::new(None),
        }
    }

    pub fn traffic(&self) -> Option<Arc<TrafficCollector>> {
        self.traffic.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    pub fn set_traffic(&self, traffic: Option<Arc<TrafficCollector>>) {
        *self.traffic.lock().unwrap_or_else(PoisonError::into_inner) = traffic;
    }

    /// `@synchronized`.
    pub(crate) fn synchronized<T>(&self, body: impl FnOnce() -> Result<T>) -> Result<T> {
        let _guard = self.lock.lock();
        body()
    }

    /// `@lifecycle_synchronized`: the accounting operation boundary before manager state.
    pub(crate) fn lifecycle<T>(&self, body: impl FnOnce(Option<&TrafficCollector>) -> Result<T>) -> Result<T> {
        let traffic = self.traffic();
        let _operation = traffic.as_ref().map(|t| t.operation());
        let _guard = self.lock.lock();
        body(traffic.as_deref())
    }

    fn caddyfile(&self) -> &Path {
        &self.settings.caddyfile
    }

    pub(crate) fn transaction_file(&self) -> PathBuf {
        self.settings
            .state_file
            .parent()
            .map(|p| p.join("transaction.json"))
            .unwrap_or_else(|| "transaction.json".into())
    }

    fn recovery_pending(&self) -> bool {
        self.recovery_failed.load(Ordering::SeqCst) || exists(&self.transaction_file())
    }

    // ------------------------------------------------------------------ lifecycle

    pub fn bootstrap(&self) -> Result<()> {
        self.lifecycle(|traffic| {
            assert_regular(self.caddyfile())?;
            if exists(&self.transaction_file()) {
                self.recover_transaction()?;
            }
            if exists(&self.settings.state_file) {
                assert_regular(&self.settings.state_file)?;
                let state = self.read_state()?;
                let text = read_text(self.caddyfile())?;
                if !text.contains(ACCOUNTING_BEGIN) && !text.contains(ACCOUNTING_END) {
                    self.migrate_accounting(&state, &text)?;
                } else {
                    self.assert_consistent(&state)?;
                }
                if let Some(traffic) = traffic {
                    for row in state["tombstones"].as_array().into_iter().flatten() {
                        traffic.archive_user(row["username"].as_str().unwrap_or(""))?;
                    }
                }
                let fresh = self.read_state()?;
                return self.refresh_router_credential(fresh);
            }
            self.initial_import()
        })
    }

    fn initial_import(&self) -> Result<()> {
        let text = read_text(self.caddyfile())?;
        let legacy = caddyfile::legacy_credentials(&text)?;
        for (username, _) in &legacy {
            if state::valid_username(&Value::from(username.as_str())).is_err() {
                return Err(Error::conflict("reserved accounting username in imported credentials"));
            }
        }
        let users: Vec<Value> = legacy
            .iter()
            .map(|(username, password)| {
                let created = now_iso();
                json!({
                    "username": username,
                    "password": password,
                    "enabled": true,
                    "quota_bytes": null,
                    "disabled_reason": null,
                    "created_at": created,
                    "updated_at": now_iso(),
                })
            })
            .collect();
        if users.is_empty() {
            return Err(Error::conflict("no NaiveProxy credentials found for initial import"));
        }
        let state = json!({"version": 1, "host": self.settings.public_host, "users": users, "tombstones": []});
        let rendered = caddyfile::render_initial(&text, &state)?;
        self.fs.durable_mkdir(&self.settings.backup_dir, 0o700)?;
        let stamp = backup_stamp();
        let config_backup = self.settings.backup_dir.join(format!("{stamp}.Caddyfile"));
        let state_backup = self.settings.backup_dir.join(format!("{stamp}.users.json"));
        self.fs.atomic_write(&config_backup, &std::fs::read(self.caddyfile())?, 0o600)?;
        self.fs.atomic_write(&state_backup, b"", 0o600)?;
        let mut transaction = Map::new();
        transaction.insert("version".into(), json!(1));
        transaction.insert("phase".into(), json!("bootstrap_prepared"));
        transaction.insert("config_backup".into(), json!(file_name(&config_backup)));
        transaction.insert("state_backup".into(), json!(file_name(&state_backup)));
        transaction.insert("state_existed".into(), json!(false));
        self.write_transaction(&transaction)?;
        self.write_validated_config(&rendered)?;
        self.fs.atomic_write(&self.settings.state_file, &state::encode_state(&state), 0o600)?;
        self.clear_transaction()?;
        self.prune_backups()
    }

    pub fn health(&self) -> Value {
        let traffic = self.traffic();
        let ready = (|| -> Result<()> {
            let _operation = traffic.as_ref().map(|t| t.operation());
            let _guard = self.lock.lock();
            if self.recovery_pending() {
                return Err(Error::recovery("transaction recovery required"));
            }
            let state = self.read_state()?;
            self.assert_consistent(&state)?;
            (self.hooks.probe)()?;
            if let Some(traffic) = &traffic {
                // Health reports; it never rewrites the managed config. Quota enforcement runs
                // on its own schedule.
                traffic.collect()?;
                if traffic.health()?.get("ready") != Some(&Value::Bool(true)) {
                    return Err(Error::conflict("traffic accounting is unavailable"));
                }
            }
            Ok(())
        })()
        .is_ok();
        json!({"ready": ready, "host": self.settings.public_host})
    }

    // ------------------------------------------------------------------ users

    pub fn list_users(&self) -> Result<Value> {
        self.synchronized(|| {
            let state = self.read_state()?;
            let rows: Vec<Value> = users(&state)
                .iter()
                .map(|row| {
                    json!({
                        "username": row["username"],
                        "enabled": is_truthy(&row["enabled"]),
                        "quota_bytes": row["quota_bytes"],
                        "disabled_reason": row["disabled_reason"],
                        "lane": row.get("lane").cloned().unwrap_or(Value::Null),
                    })
                })
                .collect();
            Ok(Value::Array(rows))
        })
    }

    pub fn traffic_report(&self) -> Result<Value> {
        let Some(traffic) = self.traffic() else {
            return Err(Error::conflict("traffic accounting is unavailable"));
        };
        let _operation = traffic.operation();
        let _guard = self.lock.lock();
        match traffic.collect().and_then(|_| traffic.list_traffic()) {
            Ok(report) => Ok(report),
            Err(err @ (Error::Conflict { .. } | Error::Recovery(_))) => Err(err),
            Err(err) if err.is_runtime() => Err(Error::conflict("traffic accounting is degraded")),
            Err(err) => Err(err),
        }
    }

    /// Collects completed CONNECT records and disables newly exhausted users.
    pub fn enforce_quotas(&self) -> Result<Vec<String>> {
        let Some(traffic) = self.traffic() else { return Ok(Vec::new()) };
        let _operation = traffic.operation();
        let _guard = self.lock.lock();
        traffic.collect()?;
        let report = traffic.list_traffic()?;
        self.enforce_quotas_from_report(&report)
    }

    /// Payload bytes recorded for a user, or 0 when accounting is unavailable.
    fn used_bytes(&self, traffic: Option<&TrafficCollector>, username: &str) -> Result<i64> {
        let Some(traffic) = traffic else { return Ok(0) };
        traffic.collect()?;
        let report = traffic.list_traffic()?;
        Ok(report["users"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|row| row["username"].as_str() == Some(username) && state::exact_int(&row["total_bytes"]).is_some())
            .and_then(|row| row["total_bytes"].as_i64())
            .unwrap_or(0))
    }

    fn enforce_quotas_from_report(&self, report: &Value) -> Result<Vec<String>> {
        let mut usage = std::collections::HashMap::new();
        for row in report["users"].as_array().into_iter().flatten() {
            if let (Some(name), Some(total)) = (row["username"].as_str(), state::exact_int(&row["total_bytes"])) {
                usage.insert(name.to_string(), total);
            }
        }
        let mut state = self.read_state()?;
        let mut exhausted = Vec::new();
        for row in users_mut(&mut state)?.iter_mut().filter_map(Value::as_object_mut) {
            let Some(quota) = row["quota_bytes"].as_i64() else { continue };
            let name = row["username"].as_str().unwrap_or("").to_string();
            if is_enabled(row) && usage.get(&name).copied().unwrap_or(0) >= quota {
                row.insert("enabled".into(), json!(false));
                row.insert("disabled_reason".into(), json!("quota"));
                row.insert("updated_at".into(), json!(now_iso()));
                exhausted.push(name);
            }
        }
        if !exhausted.is_empty() {
            self.apply(state)?;
        }
        Ok(exhausted)
    }

    pub fn reset_traffic(&self, username: &str) -> Result<Value> {
        let Some(traffic) = self.traffic() else {
            return Err(Error::conflict("traffic accounting is unavailable"));
        };
        let _operation = traffic.operation();
        let _guard = self.lock.lock();
        find(&self.read_state()?, username)?;
        let outcome = traffic.drain().and_then(|drained| {
            if !drained {
                return Err(Error::conflict("traffic backlog remains pending"));
            }
            traffic.reset(username)
        });
        match outcome {
            Err(err @ Error::Conflict { .. }) => Err(err),
            Err(err) if err.is_runtime() => Err(Error::conflict("traffic accounting is degraded")),
            other => other,
        }
    }

    pub fn managed_usernames(&self) -> Result<std::collections::HashSet<String>> {
        self.synchronized(|| Ok(state::usernames(&self.read_state()?)))
    }

    pub fn reveal(&self, username: &str) -> Result<Value> {
        self.synchronized(|| Ok(self.reveal_row(find(&self.read_state()?, username)?)))
    }

    fn reveal_row(&self, row: &Map<String, Value>) -> Value {
        let username = row["username"].as_str().unwrap_or("");
        let user = quote(username);
        let password = quote(row["password"].as_str().unwrap_or(""));
        let proxy_url = format!("https://{user}:{password}@{}", self.settings.public_host);
        json!({
            "username": username,
            "proxy_url": proxy_url,
            "config": {"listen": "socks://127.0.0.1:1080", "proxy": proxy_url},
        })
    }

    pub fn create(
        &self,
        username: &Value,
        quota_bytes: &Value,
        password: Option<&str>,
        operation_id: Option<&str>,
    ) -> Result<Value> {
        self.lifecycle(|_| {
            state::valid_username(username)?;
            state::validate_quota(quota_bytes)?;
            state::validate_password(password)?;
            let username = username.as_str().expect("validated");
            let mut state = self.read_state()?;
            if let Some(replayed) = replay(&state, operation_id, "create", username)? {
                return Ok(replayed);
            }
            if users(&state).iter().any(|row| row["username"].as_str() == Some(username)) {
                return Err(Error::conflict("user already exists"));
            }
            let retired = state["tombstones"].as_array().into_iter().flatten();
            if retired.into_iter().any(|row| row["username"].as_str() == Some(username)) {
                return Err(Error::conflict("username is permanently retired"));
            }
            let timestamp = now_iso();
            let row = json!({
                "username": username,
                "password": password.map(String::from).unwrap_or_else(|| token_urlsafe(18)),
                "enabled": true,
                "quota_bytes": quota_bytes,
                "disabled_reason": null,
                "created_at": timestamp,
                "updated_at": timestamp,
            });
            let result = self.reveal_row(object(&row)?);
            users_mut(&mut state)?.push(row);
            remember(&mut state, operation_id, "create", username, &result)?;
            self.apply(state)?;
            Ok(result)
        })
    }

    pub fn rotate(&self, username: &str, password: Option<&str>, operation_id: Option<&str>) -> Result<Value> {
        self.lifecycle(|_| {
            state::validate_password(password)?;
            let mut state = self.read_state()?;
            if let Some(replayed) = replay(&state, operation_id, "rotate", username)? {
                return Ok(replayed);
            }
            let row = find_mut(&mut state, username)?;
            row.insert("password".into(), json!(password.map(String::from).unwrap_or_else(|| token_urlsafe(18))));
            row.insert("updated_at".into(), json!(now_iso()));
            let result = self.reveal_row(row);
            remember(&mut state, operation_id, "rotate", username, &result)?;
            self.apply(state)?;
            Ok(result)
        })
    }

    pub fn set_enabled(&self, username: &str, enabled: bool) -> Result<Value> {
        self.lifecycle(|traffic| {
            let mut state = self.read_state()?;
            let quota = find(&state, username)?["quota_bytes"].as_i64();
            if enabled {
                if let Some(quota) = quota {
                    if self.used_bytes(traffic, username)? >= quota {
                        return Err(Error::conflict_code(
                            "quota exhausted; reset traffic or remove quota first",
                            "quota_exhausted",
                        ));
                    }
                }
            }
            let row = find_mut(&mut state, username)?;
            row.insert("enabled".into(), json!(enabled));
            row.insert("disabled_reason".into(), if enabled { Value::Null } else { json!("manual") });
            row.insert("updated_at".into(), json!(now_iso()));
            let reason = row["disabled_reason"].clone();
            self.apply(state)?;
            Ok(json!({"username": username, "enabled": enabled, "disabled_reason": reason}))
        })
    }

    pub fn set_quota(&self, username: &str, quota_bytes: &Value) -> Result<Value> {
        self.lifecycle(|traffic| {
            state::validate_quota(quota_bytes)?;
            let mut state = self.read_state()?;
            find(&state, username)?;
            let used = self.used_bytes(traffic, username)?;
            let row = find_mut(&mut state, username)?;
            row.insert("quota_bytes".into(), quota_bytes.clone());
            let quota = quota_bytes.as_i64();
            if is_enabled(row) && quota.is_some_and(|q| used >= q) {
                row.insert("enabled".into(), json!(false));
                row.insert("disabled_reason".into(), json!("quota"));
            } else if row["disabled_reason"].as_str() == Some("quota") && quota.is_none_or(|q| used < q) {
                // The quota no longer holds this user back, but access stays off until the
                // operator enables it: that remains a separate decision.
                row.insert("disabled_reason".into(), json!("manual"));
            }
            row.insert("updated_at".into(), json!(now_iso()));
            let view = json!({
                "username": username,
                "quota_bytes": quota_bytes,
                "enabled": row["enabled"],
                "disabled_reason": row["disabled_reason"],
            });
            self.apply(state)?;
            Ok(view)
        })
    }

    pub fn delete(&self, username: &str) -> Result<()> {
        self.lifecycle(|traffic| {
            let Some(traffic) = traffic else {
                return Err(Error::conflict("traffic accounting is unavailable"));
            };
            let mut state = self.read_state()?;
            find(&state, username)?;
            match traffic.drain() {
                Ok(true) => {}
                Ok(false) => return Err(Error::conflict("traffic backlog remains pending")),
                Err(err @ Error::Conflict { .. }) => return Err(err),
                Err(err) if err.is_runtime() => return Err(Error::conflict("traffic accounting is degraded")),
                Err(err) => return Err(err),
            }
            users_mut(&mut state)?.retain(|row| row["username"].as_str() != Some(username));
            state["tombstones"]
                .as_array_mut()
                .ok_or_else(|| Error::Key("'tombstones'".into()))?
                .push(json!({"username": username, "deleted_at": now_iso()}));
            self.apply(state)?;
            traffic.archive_user(username)
        })
    }

    // ------------------------------------------------------------------ transactions

    fn backup_pair(&self) -> Result<(PathBuf, PathBuf)> {
        self.fs.durable_mkdir(&self.settings.backup_dir, 0o700)?;
        let stamp = backup_stamp();
        Ok((
            self.settings.backup_dir.join(format!("{stamp}.Caddyfile")),
            self.settings.backup_dir.join(format!("{stamp}.users.json")),
        ))
    }

    fn prepared(config_backup: &Path, state_backup: &Path) -> Map<String, Value> {
        let mut transaction = Map::new();
        transaction.insert("version".into(), json!(1));
        transaction.insert("phase".into(), json!("prepared"));
        transaction.insert("config_backup".into(), json!(file_name(config_backup)));
        transaction.insert("state_backup".into(), json!(file_name(state_backup)));
        transaction
    }

    /// The failure path of every transaction: journal `recovery_failed`, put both files back,
    /// validate, reload and probe the restored generation; the original error is returned
    /// unless the restore itself failed.
    fn roll_back(
        &self,
        transaction: &mut Map<String, Value>,
        config_before: &[u8],
        state_before: &[u8],
        operation_error: Error,
    ) -> Error {
        self.recovery_failed.store(true, Ordering::SeqCst);
        let recovery_from = transaction["phase"].clone();
        transaction.insert("phase".into(), json!("recovery_failed"));
        transaction.insert("recovery_from".into(), recovery_from);
        let restored = (|| -> Result<()> {
            self.write_transaction(transaction)?;
            self.fs.atomic_write(self.caddyfile(), config_before, self.settings.caddyfile_mode)?;
            self.fs.atomic_write(&self.settings.state_file, state_before, 0o600)?;
            self.validate_config(self.caddyfile())?;
            (self.hooks.reload)()?;
            (self.hooks.probe)()
        })();
        if restored.is_err() {
            return Error::recovery("rollback failed; manager requires recovery");
        }
        if let Err(err) = self.clear_transaction() {
            return err;
        }
        self.recovery_failed.store(false, Ordering::SeqCst);
        if let Err(err) = self.prune_backups() {
            return err;
        }
        operation_error
    }

    /// `_apply`: the user block (and lanes) rendered from `desired`, in one transaction.
    pub(crate) fn apply(&self, desired: Value) -> Result<()> {
        if self.recovery_pending() {
            return Err(Error::recovery("transaction recovery required before mutation"));
        }
        let current = self.read_state()?;
        self.assert_consistent(&current)?;
        let config_before = std::fs::read(self.caddyfile())?;
        let state_before = std::fs::read(&self.settings.state_file)?;
        let text = String::from_utf8(config_before.clone()).map_err(|_| Error::value("'utf-8' codec can't decode"))?;
        let rendered = caddyfile::render_managed(&text, &desired)?;
        self.transact(&rendered, &state::encode_state(&desired), &config_before, &state_before, None)
    }

    /// `_commit`: a rendered Caddyfile that is not a user change, with an optional read-back
    /// of the running configuration.
    pub(crate) fn commit(&self, rendered: &str, desired: &Value, readback: Option<Readback>) -> Result<()> {
        if self.recovery_pending() {
            return Err(Error::recovery("transaction recovery required before mutation"));
        }
        let config_before = std::fs::read(self.caddyfile())?;
        let state_before = std::fs::read(&self.settings.state_file)?;
        self.transact(rendered, &state::encode_state(desired), &config_before, &state_before, readback)
    }

    fn transact(
        &self,
        rendered: &str,
        desired: &[u8],
        config_before: &[u8],
        state_before: &[u8],
        readback: Option<Readback>,
    ) -> Result<()> {
        let (config_backup, state_backup) = self.backup_pair()?;
        self.fs.atomic_write(&config_backup, config_before, 0o600)?;
        self.fs.atomic_write(&state_backup, state_before, 0o600)?;
        let mut transaction = Self::prepared(&config_backup, &state_backup);
        self.write_transaction(&transaction)?;
        let outcome = (|| -> Result<()> {
            self.write_validated_config(rendered)?;
            self.fs.atomic_write(&self.settings.state_file, desired, 0o600)?;
            transaction.insert("phase".into(), json!("rollback_pending"));
            self.write_transaction(&transaction)?;
            (self.hooks.reload)()?;
            (self.hooks.probe)()?;
            if let Some(check) = &readback {
                check(&(self.hooks.validate)(self.caddyfile())?)?;
            }
            Ok(())
        })();
        if let Err(err) = outcome {
            return Err(self.roll_back(&mut transaction, config_before, state_before, err));
        }
        self.clear_transaction()?;
        self.prune_backups()
    }

    fn migrate_accounting(&self, state: &Value, text: &str) -> Result<()> {
        let actual = caddyfile::managed_credentials(text)?;
        let expected: Vec<(String, String)> = users(state)
            .iter()
            .filter_map(Value::as_object)
            .filter(|row| is_enabled(row))
            .map(|row| (text_field(row, "username"), text_field(row, "password")))
            .collect();
        if actual != expected {
            return Err(Error::conflict("managed Caddy credentials changed outside manager"));
        }
        self.validate_config(self.caddyfile())?;
        let rendered = caddyfile::render_accounting_migration(text)?;
        let config_before = std::fs::read(self.caddyfile())?;
        let state_before = std::fs::read(&self.settings.state_file)?;
        let (config_backup, state_backup) = self.backup_pair()?;
        self.fs.atomic_write(&config_backup, &config_before, 0o600)?;
        self.fs.atomic_write(&state_backup, &state_before, 0o600)?;
        let mut transaction = Self::prepared(&config_backup, &state_backup);
        transaction.insert("operation".into(), json!("accounting_migration"));
        self.write_transaction(&transaction)?;
        let outcome = (|| -> Result<()> {
            self.write_validated_config(&rendered)?;
            self.fs.atomic_write(&self.settings.state_file, &state_before, 0o600)?;
            transaction.insert("phase".into(), json!("files_replaced"));
            self.write_transaction(&transaction)?;
            transaction.insert("phase".into(), json!("rollback_pending"));
            self.write_transaction(&transaction)?;
            (self.hooks.reload)()?;
            (self.hooks.probe)()
        })();
        if let Err(err) = outcome {
            return Err(self.roll_back(&mut transaction, &config_before, &state_before, err));
        }
        self.clear_transaction()?;
        self.prune_backups()
    }

    /// Writes `rendered` beside the Caddyfile, validates that file, then replaces.
    fn write_validated_config(&self, rendered: &str) -> Result<()> {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let parent = self.caddyfile().parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        self.fs.durable_mkdir(parent, 0o700)?;
        let (mut file, temporary) = mkstemp(parent, ".Caddyfile.naive.")?;
        let outcome = (|| -> Result<()> {
            file.set_permissions(std::fs::Permissions::from_mode(self.settings.caddyfile_mode))?;
            file.write_all(rendered.as_bytes())?;
            file.flush()?;
            file.sync_all()?;
            self.validate_config(&temporary)?;
            self.fs.replace(&temporary, self.caddyfile())?;
            std::fs::set_permissions(self.caddyfile(), std::fs::Permissions::from_mode(self.settings.caddyfile_mode))?;
            self.fs.fsync_directory(parent)
        })();
        let _ = std::fs::remove_file(&temporary);
        outcome
    }

    // ------------------------------------------------------------------ state

    pub(crate) fn read_state(&self) -> Result<Value> {
        assert_regular(&self.settings.state_file)?;
        let bytes = std::fs::read(&self.settings.state_file).map_err(|_| Error::conflict("invalid manager state"))?;
        let parsed = state::parse_state(&bytes)?;
        let (secs, micros) = now_parts();
        state::normalise(parsed, &self.settings.public_host, secs as f64 + micros as f64 / 1e6)
    }

    pub(crate) fn read_transaction(&self) -> Result<Map<String, Value>> {
        assert_regular(&self.transaction_file())?;
        let invalid = || Error::recovery("invalid transaction journal");
        let text = std::fs::read(self.transaction_file()).map_err(|_| invalid())?;
        let value: Value =
            std::str::from_utf8(&text).ok().and_then(|text| serde_json::from_str(text).ok()).ok_or_else(invalid)?;
        let transaction = value.as_object().ok_or_else(invalid)?.clone();
        let phases = ["bootstrap_prepared", "prepared", "files_replaced", "rollback_pending", "recovery_failed"];
        let version_ok = matches!(transaction.get("version"), Some(Value::Number(n)) if n.as_i64() == Some(1));
        let phase = transaction.get("phase").and_then(Value::as_str).unwrap_or("");
        if !version_ok || !phases.contains(&phase) {
            return Err(invalid());
        }
        let mut allowed: Vec<&str> = vec!["version", "phase", "config_backup", "state_backup"];
        match transaction.get("operation") {
            None | Some(Value::Null) => {}
            Some(Value::String(op)) if op == "accounting_migration" => allowed.push("operation"),
            Some(_) => return Err(invalid()),
        }
        let state_existed_false = transaction.get("state_existed") == Some(&Value::Bool(false));
        let valid_shape = match phase {
            "bootstrap_prepared" => {
                allowed.push("state_existed");
                state_existed_false
            }
            "recovery_failed" => {
                allowed.push("recovery_from");
                let origin = transaction.get("recovery_from").and_then(Value::as_str);
                let mut ok =
                    matches!(origin, Some("bootstrap_prepared" | "prepared" | "files_replaced" | "rollback_pending"));
                if origin == Some("bootstrap_prepared") {
                    allowed.push("state_existed");
                    ok = ok && state_existed_false;
                }
                ok
            }
            _ => true,
        };
        let keys_match = transaction.len() == allowed.len() && allowed.iter().all(|key| transaction.contains_key(*key));
        if !valid_shape || !keys_match {
            return Err(invalid());
        }
        let config_name = transaction.get("config_backup").and_then(Value::as_str);
        let state_name = transaction.get("state_backup").and_then(Value::as_str);
        let (Some(config_name), Some(state_name)) = (config_name, state_name) else { return Err(invalid()) };
        let config_stem = config_name.strip_suffix(".Caddyfile");
        let state_stem = state_name.strip_suffix(".users.json");
        if !is_bare_name(config_name)
            || !is_bare_name(state_name)
            || config_stem.is_none()
            || state_stem.is_none()
            || config_stem != state_stem
            || config_stem == Some("")
        {
            return Err(invalid());
        }
        Ok(transaction)
    }

    pub(crate) fn write_transaction(&self, transaction: &Map<String, Value>) -> Result<()> {
        let mut text = crate::pyjson::dumps(&Value::Object(transaction.clone()), crate::pyjson::COMPACT);
        text.push('\n');
        self.fs.atomic_write(&self.transaction_file(), text.as_bytes(), 0o600)?;
        self.fs.after_transaction(transaction)
    }

    fn clear_transaction(&self) -> Result<()> {
        self.fs.durable_unlink(&self.transaction_file())
    }

    fn recover_transaction(&self) -> Result<()> {
        let mut transaction = self.read_transaction()?;
        let original = transaction.get("recovery_from").cloned().unwrap_or_else(|| transaction["phase"].clone());
        let original_phase = original.as_str().unwrap_or("").to_string();
        transaction.insert("phase".into(), json!("recovery_failed"));
        transaction.insert("recovery_from".into(), original);
        self.write_transaction(&transaction)?;
        let restore_backups = || -> Result<()> {
            let config_backup = self.settings.backup_dir.join(transaction["config_backup"].as_str().unwrap_or(""));
            let state_backup = self.settings.backup_dir.join(transaction["state_backup"].as_str().unwrap_or(""));
            assert_regular(&config_backup)?;
            assert_regular(&state_backup)?;
            self.fs.atomic_write(self.caddyfile(), &std::fs::read(&config_backup)?, self.settings.caddyfile_mode)?;
            if transaction.get("state_existed") != Some(&Value::Bool(false)) {
                self.fs.atomic_write(&self.settings.state_file, &std::fs::read(&state_backup)?, 0o600)
            } else {
                self.fs.durable_unlink(&self.settings.state_file)
            }
        };
        let activate_current = || -> Result<()> {
            let state = self.read_state()?;
            self.assert_consistent(&state)?;
            (self.hooks.reload)()?;
            (self.hooks.probe)()
        };
        let activate_pre_accounting = || -> Result<()> {
            let state = self.read_state()?;
            let text = read_text(self.caddyfile())?;
            let actual = caddyfile::managed_credentials(&text)?;
            let expected: Vec<(String, String)> = users(&state)
                .iter()
                .filter_map(Value::as_object)
                .filter(|row| is_enabled(row))
                .map(|row| (text_field(row, "username"), text_field(row, "password")))
                .collect();
            if actual != expected {
                return Err(Error::conflict("managed Caddy credentials changed outside manager"));
            }
            self.validate_config(self.caddyfile())?;
            (self.hooks.reload)()?;
            (self.hooks.probe)()
        };
        let outcome = (|| -> Result<()> {
            if original_phase == "bootstrap_prepared" {
                restore_backups()?;
            } else if transaction.get("operation").and_then(Value::as_str) == Some("accounting_migration") {
                restore_backups()?;
                activate_pre_accounting()?;
            } else if matches!(original_phase.as_str(), "prepared" | "rollback_pending" | "recovery_failed")
                // `files_replaced`: the new generation is complete unless it fails to activate.
                || activate_current().is_err()
            {
                restore_backups()?;
                activate_current()?;
            }
            self.clear_transaction()
        })();
        match outcome {
            Ok(()) => {
                self.recovery_failed.store(false, Ordering::SeqCst);
                Ok(())
            }
            Err(_) => {
                self.recovery_failed.store(true, Ordering::SeqCst);
                Err(Error::recovery("transaction recovery failed"))
            }
        }
    }

    pub(crate) fn assert_consistent(&self, state: &Value) -> Result<()> {
        let text = read_text(self.caddyfile())?;
        caddyfile::assert_accounting_config(&text)?;
        let actual = caddyfile::managed_credentials(&text)?;
        let expected: Vec<(String, String)> = users(state)
            .iter()
            .filter_map(Value::as_object)
            .filter(|row| is_enabled(row) && row.get("lane").is_none_or(Value::is_null))
            .map(|row| (text_field(row, "username"), text_field(row, "password")))
            .collect();
        if actual != expected {
            return Err(Error::conflict("managed Caddy credentials changed outside manager"));
        }
        let lanes: Vec<Vec<(String, String)>> = caddyfile::lane_handlers(state)
            .into_iter()
            .filter(|(users, _)| !users.is_empty())
            .map(|(users, _)| users)
            .collect();
        if crate::lanes::lane_credentials(&text)? != lanes {
            return Err(Error::conflict("managed Caddy lane credentials changed outside manager"));
        }
        self.validate_config(self.caddyfile())
    }

    fn validate_config(&self, path: &Path) -> Result<()> {
        let text = read_text(path)?;
        let mut expected: Vec<usize> = crate::lanes::lane_credentials(&text)?.iter().map(|users| users.len()).collect();
        expected.push(caddyfile::managed_credentials(&text)?.len());
        let config = (self.hooks.validate)(path)?;
        assert_adapted_semantics(&config, &expected)
    }

    fn prune_backups(&self) -> Result<()> {
        let mut backups: Vec<PathBuf> = match std::fs::read_dir(&self.settings.backup_dir) {
            Ok(entries) => entries
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".Caddyfile"))
                .map(|entry| entry.path())
                .collect(),
            Err(_) => Vec::new(),
        };
        backups.sort();
        backups.reverse();
        for old in backups.iter().skip(20) {
            remove_missing_ok(old)?;
            let name = file_name(old);
            let pair = old.with_file_name(format!("{}.users.json", name.strip_suffix(".Caddyfile").unwrap_or(&name)));
            remove_missing_ok(&pair)?;
        }
        Ok(())
    }
}

pub type Readback = Box<dyn Fn(&Value) -> Result<()>>;

fn remove_missing_ok(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn file_name(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

fn text_field(row: &Map<String, Value>, key: &str) -> String {
    row.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Every dict with a string `handler`, in document order (pre-order walk).
pub(crate) fn handlers(config: &Value) -> Vec<&Map<String, Value>> {
    fn walk<'a>(value: &'a Value, found: &mut Vec<&'a Map<String, Value>>) {
        match value {
            Value::Object(map) => {
                if map.get("handler").is_some_and(Value::is_string) {
                    found.push(map);
                }
                for child in map.values() {
                    walk(child, found);
                }
            }
            Value::Array(items) => items.iter().for_each(|child| walk(child, found)),
            _ => {}
        }
    }
    let mut found = Vec::new();
    walk(config, &mut found);
    found
}

/// One `forward_proxy` handler per expected count, in Caddyfile order — the lane handlers
/// first, the service's own last — each with exactly that many credentials, and no
/// `authentication` handler anywhere.
pub fn assert_adapted_semantics(config: &Value, expected: &[usize]) -> Result<()> {
    if !config.is_object() {
        return Err(Error::conflict("invalid adapted Caddy configuration"));
    }
    let all = handlers(config);
    let forward: Vec<_> = all.iter().filter(|h| h["handler"] == "forward_proxy").collect();
    let authentication = all.iter().any(|h| h["handler"] == "authentication");
    if forward.len() != expected.len() || authentication {
        return Err(Error::conflict("unexpected proxy or authentication handler"));
    }
    for (node, count) in forward.iter().zip(expected) {
        let ok = match node.get("auth_credentials") {
            Some(Value::Array(credentials)) => {
                credentials.len() == *count && credentials.iter().all(|v| v.as_str().is_some_and(|s| !s.is_empty()))
            }
            _ => false,
        };
        if !ok {
            return Err(Error::conflict("adapted proxy credentials do not match managed state"));
        }
    }
    Ok(())
}

/// The recorded result when this exact request already completed. A lost response is the
/// normal case: the caller retries with the same id and must get the same credential back.
fn replay(state: &Value, operation_id: Option<&str>, operation: &str, username: &str) -> Result<Option<Value>> {
    let Some(operation_id) = operation_id else { return Ok(None) };
    if !state::is_operation_id(operation_id) {
        return Err(Error::value("invalid operation id"));
    }
    let Some(record) = state["operations"].get(operation_id) else { return Ok(None) };
    if record["operation"].as_str() != Some(operation) || record["username"].as_str() != Some(username) {
        return Err(Error::conflict_code("operation id already used for another request", "operation_conflict"));
    }
    let mut result = record["result"].clone();
    object_mut(&mut result)?.insert("replayed".into(), json!(true));
    Ok(Some(result))
}

fn remember(
    state: &mut Value,
    operation_id: Option<&str>,
    operation: &str,
    username: &str,
    result: &Value,
) -> Result<()> {
    let Some(operation_id) = operation_id else { return Ok(()) };
    let operations =
        state.get_mut("operations").and_then(Value::as_object_mut).ok_or_else(|| Error::Key("'operations'".into()))?;
    operations.insert(
        operation_id.to_string(),
        json!({"operation": operation, "username": username, "completed_at": now_iso(), "result": result}),
    );
    Ok(())
}
