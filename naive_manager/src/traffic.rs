//! Durably account complete Caddy CONNECT access-log records exactly once.
//!
//! Caddy rotates the access log by renaming it (timberjack names); every file is tracked by
//! its (device, inode) identity with the offset consumed so far and a SHA-256 of that prefix,
//! so a rewritten or truncated file is detected instead of counted twice. The database is the
//! Python manager's SQLite file, schema and pragmas unchanged.

use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::pyutil::{now_iso, ReentrantGuard, ReentrantMutex};

pub const MAX_COUNTER: i64 = i64::MAX;
pub const REDACTION_SENTINEL: &str = "invalid";
pub const MIB: u64 = 1024 * 1024;
pub const ACCOUNTING_ROLL_SIZE_BYTES: u64 = 10 * MIB;
pub const ACCOUNTING_ROLL_KEEP: usize = 10;
pub const ACCOUNTING_RETAINED_BYTES: u64 = ACCOUNTING_ROLL_SIZE_BYTES * (ACCOUNTING_ROLL_KEEP as u64 + 1);
pub const ACCOUNTING_MAX_VERIFY_BYTES: u64 = 128 * MIB;

/// The schema exactly as the Python collector created it (SQLite keeps this text).
const SCHEMA: &str = "
            CREATE TABLE IF NOT EXISTS traffic_files (
                device INTEGER NOT NULL,
                inode INTEGER NOT NULL,
                offset INTEGER NOT NULL CHECK(offset >= 0),
                path TEXT NOT NULL,
                tail_digest BLOB,
                discarding INTEGER NOT NULL DEFAULT 0 CHECK(discarding IN (0, 1)),
                observed_mtime_ns INTEGER,
                observed_ctime_ns INTEGER,
                file_size INTEGER,
                observed_head_digest BLOB,
                observed_tail_digest BLOB,
                consumed_prefix_digest BLOB,
                PRIMARY KEY(device, inode)
            );
            CREATE TABLE IF NOT EXISTS traffic_counters (
                username TEXT PRIMARY KEY,
                upload_bytes INTEGER NOT NULL CHECK(upload_bytes >= 0),
                download_bytes INTEGER NOT NULL CHECK(download_bytes >= 0),
                period_start TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS traffic_archives (
                username TEXT PRIMARY KEY,
                upload_bytes INTEGER NOT NULL CHECK(upload_bytes >= 0),
                download_bytes INTEGER NOT NULL CHECK(download_bytes >= 0),
                period_start TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                archived_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS accounting_state (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                error TEXT NOT NULL,
                detected_at TEXT NOT NULL
            );
            ";

/// Columns added to `traffic_files` after its first release, in the order Python added them.
const ADDED_COLUMNS: [(&str, &str); 7] = [
    (
        "discarding",
        "ALTER TABLE traffic_files ADD COLUMN discarding INTEGER NOT NULL DEFAULT 0 CHECK(discarding IN (0, 1))",
    ),
    ("observed_mtime_ns", "ALTER TABLE traffic_files ADD COLUMN observed_mtime_ns INTEGER"),
    ("observed_ctime_ns", "ALTER TABLE traffic_files ADD COLUMN observed_ctime_ns INTEGER"),
    ("file_size", "ALTER TABLE traffic_files ADD COLUMN file_size INTEGER"),
    ("observed_head_digest", "ALTER TABLE traffic_files ADD COLUMN observed_head_digest BLOB"),
    ("observed_tail_digest", "ALTER TABLE traffic_files ADD COLUMN observed_tail_digest BLOB"),
    ("consumed_prefix_digest", "ALTER TABLE traffic_files ADD COLUMN consumed_prefix_digest BLOB"),
];

pub type ManagedUsers = Box<dyn Fn() -> Result<HashSet<String>> + Send + Sync>;

#[derive(Debug, Clone)]
pub struct Options {
    pub max_line_bytes: u64,
    pub max_read_bytes: u64,
    pub max_verify_bytes: u64,
    pub expected_retained_bytes: Option<u64>,
    pub max_drain_rounds: u32,
    pub max_rotations: usize,
    pub max_directory_entries: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_line_bytes: MIB,
            max_read_bytes: 32 * MIB,
            max_verify_bytes: 16 * MIB,
            expected_retained_bytes: None,
            max_drain_rounds: 16,
            max_rotations: ACCOUNTING_ROLL_KEEP,
            max_directory_entries: 4096,
        }
    }
}

impl Options {
    /// What the production manager runs with.
    pub fn production() -> Self {
        Self {
            max_verify_bytes: ACCOUNTING_MAX_VERIFY_BYTES,
            expected_retained_bytes: Some(ACCOUNTING_RETAINED_BYTES),
            max_rotations: ACCOUNTING_ROLL_KEEP,
            ..Self::default()
        }
    }
}

/// One log file found by discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub path: PathBuf,
    pub identity: (u64, u64),
    pub active: bool,
}

pub type CandidateHook = Box<dyn Fn(&Candidate) + Send + Sync>;
pub type Hook = Box<dyn Fn() + Send + Sync>;
pub type LengthHook = Box<dyn Fn(u64) + Send + Sync>;

/// Seams the Python suite reached through `monkeypatch`.
#[derive(Default)]
pub struct Probes {
    pub before_collect_file: Option<CandidateHook>,
    pub before_present_identities: Option<Hook>,
    pub after_present_identities: Option<Hook>,
    pub hash_prefix: Option<LengthHook>,
}

pub struct TrafficCollector {
    pub log_path: PathBuf,
    pub database_path: PathBuf,
    pub options: Options,
    managed_users: ManagedUsers,
    operation_lock: ReentrantMutex,
    db: Mutex<Option<Connection>>,
    last_error: Mutex<Option<String>>,
    pub probes: Mutex<Probes>,
}

fn runtime(message: &str) -> Error {
    Error::runtime(message)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn as_i64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| Error::Other("Python int too large to convert to SQLite INTEGER".into()))
}

/// `_assert_safe_parent_chain` of the collector: the same walk, a `RuntimeError`.
fn assert_safe_parent_chain(path: &Path) -> Result<()> {
    crate::fsops::assert_safe_parent_chain(path).map_err(|err| match err {
        Error::Conflict { .. } => runtime("accounting path parent is unsafe"),
        other => other,
    })
}

/// `os.open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)` of a regular file.
fn open_regular(path: &Path) -> Result<(File, std::fs::Metadata)> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| runtime("accounting log unavailable or unsafe"))?;
    let info = file.metadata()?;
    if !info.file_type().is_file() {
        return Err(runtime("accounting log is not a regular file"));
    }
    Ok((file, info))
}

fn digest_bytes(value: Option<rusqlite::types::Value>) -> Option<Vec<u8>> {
    match value {
        Some(rusqlite::types::Value::Blob(bytes)) => Some(bytes),
        _ => None,
    }
}

impl TrafficCollector {
    pub fn new(log_path: &Path, database_path: &Path, managed_users: ManagedUsers, options: Options) -> Result<Self> {
        if options.max_line_bytes == 0 || options.max_read_bytes <= options.max_line_bytes {
            return Err(Error::value("max_read_bytes must be greater than max_line_bytes"));
        }
        if options.max_verify_bytes == 0 {
            return Err(Error::value("max_verify_bytes must be positive"));
        }
        if let Some(retained) = options.expected_retained_bytes {
            if retained == 0 || options.max_verify_bytes < retained {
                return Err(Error::value("max_verify_bytes must cover the retained accounting footprint"));
            }
        }
        if options.max_drain_rounds == 0 {
            return Err(Error::value("max_drain_rounds must be positive"));
        }
        if options.max_directory_entries <= options.max_rotations {
            return Err(Error::value("invalid accounting directory bounds"));
        }
        assert_safe_parent_chain(log_path)?;
        assert_safe_parent_chain(database_path)?;
        if let Some(parent) = database_path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        assert_safe_parent_chain(database_path)?;
        if database_path.is_symlink() {
            return Err(runtime("accounting database is unsafe"));
        }
        if database_path.exists() {
            if !std::fs::symlink_metadata(database_path)?.file_type().is_file() {
                return Err(runtime("accounting database is unsafe"));
            }
        } else {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(database_path)?;
        }
        let db = Connection::open(database_path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(()))?;
        db.execute_batch("PRAGMA synchronous=FULL")?;
        db.execute_batch(SCHEMA)?;
        let columns: HashSet<String> = {
            let mut statement = db.prepare("PRAGMA table_info(traffic_files)")?;
            let rows = statement.query_map([], |row| row.get::<_, String>(1))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for (column, statement) in ADDED_COLUMNS {
            if !columns.contains(column) {
                db.execute_batch(statement)?;
            }
        }
        let collector = Self {
            log_path: log_path.to_path_buf(),
            database_path: database_path.to_path_buf(),
            options,
            managed_users,
            operation_lock: ReentrantMutex::default(),
            db: Mutex::new(Some(db)),
            last_error: Mutex::new(None),
            probes: Mutex::new(Probes::default()),
        };
        collector.secure_database_files()?;
        Ok(collector)
    }

    fn secure_database_files(&self) -> Result<()> {
        let base = self.database_path.as_os_str().to_owned();
        let mut wal = base.clone();
        wal.push("-wal");
        let mut shm = base.clone();
        shm.push("-shm");
        for path in [PathBuf::from(base), PathBuf::from(wal), PathBuf::from(shm)] {
            let info = match std::fs::symlink_metadata(&path) {
                Ok(info) => info,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => return Err(err.into()),
            };
            if info.file_type().is_symlink() || !info.file_type().is_file() {
                return Err(runtime("accounting database is unsafe"));
            }
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    fn database(&self) -> MutexGuard<'_, Option<Connection>> {
        lock(&self.db)
    }

    pub fn close(&self) {
        if let Some(db) = self.database().take() {
            let _ = db.close();
        }
    }

    /// Serialises lifecycle mutations with snapshots and accounting commits.
    pub fn operation(&self) -> ReentrantGuard<'_> {
        self.operation_lock.lock()
    }

    fn assert_accounting_ready(db: &Connection) -> Result<()> {
        let row: Option<String> =
            db.query_row("SELECT error FROM accounting_state WHERE singleton=1", [], |row| row.get(0)).optional()?;
        if row.is_some() {
            return Err(runtime("persistent accounting loss requires operator recovery"));
        }
        Ok(())
    }

    fn hash_prefix(&self, file: &File, length: u64) -> Result<Sha256> {
        if let Some(record) = &lock(&self.probes).hash_prefix {
            record(length);
        }
        let mut digest = Sha256::new();
        let mut cursor = 0u64;
        let mut chunk = vec![0u8; 64 * 1024];
        while cursor < length {
            let want = (length - cursor).min(chunk.len() as u64) as usize;
            let read = file.read_at(&mut chunk[..want], cursor)?;
            if read == 0 {
                return Err(runtime("accounting log changed while being inspected"));
            }
            digest.update(&chunk[..read]);
            cursor += read as u64;
        }
        Ok(digest)
    }

    /// `access-YYYY-MM-DDTHH-MM-SS.mmm-(size|rotate).json` for `access.json`.
    fn is_rotation(&self, name: &str) -> bool {
        let file_name = self.log_path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let suffix = match file_name.rfind('.') {
            Some(i) if i > 0 && i < file_name.len() - 1 => &file_name[i..],
            _ => "",
        };
        let stem = file_name.strip_suffix(suffix).unwrap_or(&file_name);
        let Some(rest) = name.strip_prefix(stem).and_then(|r| r.strip_prefix('-')) else { return false };
        let Some(rest) = rest.strip_suffix(suffix) else { return false };
        let pattern = b"dddd-dd-ddTdd-dd-dd.ddd-";
        let bytes = rest.as_bytes();
        if bytes.len() < pattern.len() {
            return false;
        }
        let stamp_ok = pattern.iter().zip(bytes).all(|(p, b)| if *p == b'd' { b.is_ascii_digit() } else { p == b });
        stamp_ok && matches!(&rest[pattern.len()..], "size" | "rotate")
    }

    /// The log directory's entries that are the active log or one of its rotations, as
    /// (active, path, inode) in directory order; every entry counts toward the bound.
    fn scan(&self) -> Result<Vec<(bool, PathBuf, u64)>> {
        use std::os::unix::fs::DirEntryExt;
        let parent = self.log_path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let active = self.log_path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
        let entries = std::fs::read_dir(parent).map_err(|_| runtime("accounting log directory unavailable"))?;
        let mut found = Vec::new();
        for (scanned, entry) in entries.enumerate() {
            if scanned + 1 > self.options.max_directory_entries {
                return Err(runtime("accounting log directory entry limit exceeded"));
            }
            let entry = entry.map_err(|_| runtime("accounting log directory unavailable"))?;
            let name = entry.file_name();
            let is_active = name == active;
            if is_active || name.to_str().is_some_and(|text| self.is_rotation(text)) {
                found.push((is_active, entry.path(), entry.ino()));
            }
        }
        Ok(found)
    }

    fn candidates(&self) -> Result<Vec<Candidate>> {
        let mut candidates: BTreeMap<(u64, u64), Candidate> = BTreeMap::new();
        for (active, path, inode) in self.scan()? {
            let (_file, info) = open_regular(&path)?;
            if inode != info.ino() {
                return Err(runtime("accounting log changed during discovery"));
            }
            let candidate = Candidate { path, identity: (info.dev(), info.ino()), active };
            let replace = match candidates.get(&candidate.identity) {
                None => true,
                Some(existing) => {
                    candidate.active || (!existing.active && candidate.path.file_name() < existing.path.file_name())
                }
            };
            if replace {
                candidates.insert(candidate.identity, candidate);
            }
            if candidates.len() > self.options.max_rotations + 1 {
                return Err(runtime("accounting log rotation limit exceeded"));
            }
        }
        if !candidates.values().any(|c| c.active) {
            return Err(runtime("active accounting log is missing"));
        }
        // Oldest rotations first and the active inode last: identity plus offset keeps this
        // ordering replay-safe across restarts and rename rotation.
        let mut sorted: Vec<Candidate> = candidates.into_values().collect();
        sorted.sort_by(|a, b| (a.active, a.path.file_name()).cmp(&(b.active, b.path.file_name())));
        Ok(sorted)
    }

    /// Rescans and opens the current names so stale discovery paths cannot drive pruning.
    fn present_identities(&self) -> Result<HashSet<(u64, u64)>> {
        if let Some(hook) = &lock(&self.probes).before_present_identities {
            hook();
        }
        let mut present = HashSet::new();
        let mut active_seen = false;
        for (active, path, inode) in self.scan()? {
            let (_file, info) = open_regular(&path)?;
            if inode != info.ino() {
                return Err(runtime("accounting log changed during discovery"));
            }
            present.insert((info.dev(), info.ino()));
            if present.len() > self.options.max_rotations + 1 {
                return Err(runtime("accounting log rotation limit exceeded"));
            }
            active_seen = active_seen || active;
        }
        if !active_seen {
            return Err(runtime("active accounting log is missing"));
        }
        if let Some(hook) = &lock(&self.probes).after_present_identities {
            hook();
        }
        Ok(present)
    }

    pub fn collect(&self) -> Result<u64> {
        let _operation = self.operation();
        let users = (self.managed_users)()?;
        self.collect_locked(&users)
    }

    fn collect_locked(&self, users: &HashSet<String>) -> Result<u64> {
        let guard = self.database();
        let outcome = (|| -> Result<u64> {
            let db = guard.as_ref().ok_or_else(closed)?;
            Self::assert_accounting_ready(db)?;
            let mut budget = self.options.max_read_bytes as i64;
            let mut verify_budget = self.options.max_verify_bytes as i64;
            let mut accepted = 0;
            for candidate in self.candidates()? {
                let (count, consumed, verified) = self.collect_file(db, &candidate, users, budget, verify_budget)?;
                accepted += count;
                budget -= consumed as i64;
                verify_budget -= verified as i64;
            }
            self.prune_consumed_deleted(db)?;
            Ok(accepted)
        })();
        *lock(&self.last_error) = outcome.as_ref().err().map(|err| err.class_name().to_string());
        outcome
    }

    fn collect_file(
        &self,
        db: &Connection,
        candidate: &Candidate,
        users: &HashSet<String>,
        budget: i64,
        verify_budget: i64,
    ) -> Result<(u64, u64, u64)> {
        if let Some(hook) = &lock(&self.probes).before_collect_file {
            hook(candidate);
        }
        let (file, info) = open_regular(&candidate.path)?;
        let identity = (info.dev(), info.ino());
        if identity != candidate.identity {
            return Err(runtime("accounting log changed during discovery"));
        }
        let (device, inode) = (as_i64(identity.0)?, as_i64(identity.1)?);
        let row: Option<(i64, i64, Option<rusqlite::types::Value>)> = db
            .query_row(
                "SELECT offset,discarding,consumed_prefix_digest FROM traffic_files WHERE device=? AND inode=?",
                params![device, inode],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let offset = row.as_ref().map(|r| r.0).unwrap_or(0).max(0) as u64;
        let mut discarding = row.as_ref().is_some_and(|r| r.1 != 0);
        let size = info.len();
        if size < offset {
            return Err(runtime("accounting log violates rename-only rotation contract"));
        }
        let stored_digest = row.as_ref().map(|r| digest_bytes(r.2.clone()));
        if row.is_some()
            && offset > 0
            && row.as_ref().is_some_and(|r| matches!(r.2, None | Some(rusqlite::types::Value::Null)))
        {
            return Err(runtime("accounting prefix cannot be verified after schema upgrade"));
        }
        let available = size - offset;
        if row.is_some() && offset as i64 > verify_budget {
            return Err(runtime("accounting prefix verification budget exceeded"));
        }
        let mut prefix = self.hash_prefix(&file, offset)?;
        if let Some(stored) = stored_digest {
            if stored.as_deref() != Some(prefix.clone().finalize().as_slice()) {
                return Err(runtime("accounting log violates rename-only rotation contract"));
            }
        }
        let data = if budget <= 0 {
            Vec::new()
        } else {
            let want = (budget as u64).min(available) as usize;
            let mut buffer = vec![0u8; want];
            let read = file.read_at(&mut buffer, offset)?;
            buffer.truncate(read);
            buffer
        };
        drop(file);

        let mut cursor = 0usize;
        let mut processed_end = 0usize;
        if discarding {
            match data.iter().position(|b| *b == b'\n') {
                None => processed_end = data.len(),
                Some(newline) => {
                    cursor = newline + 1;
                    processed_end = cursor;
                    discarding = false;
                }
            }
        }
        let remaining = &data[cursor..];
        let complete_end = remaining.iter().rposition(|b| *b == b'\n').map(|i| i + 1).unwrap_or(0);
        let complete = &remaining[..complete_end];
        if complete_end > 0 {
            processed_end = cursor + complete_end;
        }
        let trailing = remaining.len() - complete_end;
        if trailing as u64 > self.options.max_line_bytes {
            // Persist bounded discard progress, or one malformed record larger than the read
            // budget would pin this inode forever.
            processed_end = data.len();
            discarding = true;
        }
        let new_offset = offset + processed_end as u64;
        prefix.update(&data[..processed_end]);
        let consumed_prefix_digest = prefix.finalize().to_vec();

        let mut accepted = 0;
        let mut increments: Vec<(String, (i128, i128))> = Vec::new();
        let mut existing_totals: std::collections::HashMap<String, (i128, i128)> = std::collections::HashMap::new();
        let global_total: i128 = {
            let mut statement = db.prepare("SELECT upload_bytes,download_bytes FROM traffic_counters")?;
            let rows = statement.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?;
            let mut total = 0i128;
            for row in rows {
                let (upload, download) = row?;
                total += upload as i128 + download as i128;
            }
            total
        };
        let max = MAX_COUNTER as i128;
        let mut pending_global: i128 = 0;
        for raw in crate::pyutil::splitlines_bytes(complete) {
            let Some((username, upload, download)) = self.parse(raw, users) else { continue };
            let (upload, download) = (upload as i128, download as i128);
            let prior = increments.iter().find(|(name, _)| *name == username).map(|(_, v)| *v).unwrap_or((0, 0));
            if !existing_totals.contains_key(&username) {
                let existing: Option<(i64, i64)> = db
                    .query_row(
                        "SELECT upload_bytes,download_bytes FROM traffic_counters WHERE username=?",
                        params![username],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                let existing = existing.map(|(u, d)| (u as i128, d as i128)).unwrap_or((0, 0));
                existing_totals.insert(username.clone(), existing);
            }
            let base = existing_totals[&username];
            if base.0 > max - prior.0 - upload
                || base.1 > max - prior.1 - download
                || base.0 + base.1 > max - prior.0 - prior.1 - upload - download
                || global_total > max - pending_global - upload - download
            {
                continue;
            }
            let updated = (prior.0 + upload, prior.1 + download);
            match increments.iter_mut().find(|(name, _)| *name == username) {
                Some(slot) => slot.1 = updated,
                None => increments.push((username, updated)),
            }
            pending_global += upload + download;
            accepted += 1;
        }
        let now = now_iso();
        let transaction = db.unchecked_transaction()?;
        transaction.execute(
            "INSERT INTO traffic_files(device,inode,offset,path,tail_digest,discarding,\
             observed_mtime_ns,observed_ctime_ns,file_size,observed_head_digest,\
             observed_tail_digest,consumed_prefix_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) \
             ON CONFLICT(device,inode) DO UPDATE SET \
             offset=excluded.offset,path=excluded.path,tail_digest=excluded.tail_digest,\
             discarding=excluded.discarding,observed_mtime_ns=excluded.observed_mtime_ns,\
             observed_ctime_ns=excluded.observed_ctime_ns,file_size=excluded.file_size,\
             observed_head_digest=excluded.observed_head_digest,\
             observed_tail_digest=excluded.observed_tail_digest,\
             consumed_prefix_digest=excluded.consumed_prefix_digest",
            params![
                device,
                inode,
                as_i64(new_offset)?,
                candidate.path.to_string_lossy(),
                Option::<Vec<u8>>::None,
                discarding as i64,
                info.mtime() * 1_000_000_000 + info.mtime_nsec(),
                info.ctime() * 1_000_000_000 + info.ctime_nsec(),
                as_i64(size)?,
                Option::<Vec<u8>>::None,
                Option::<Vec<u8>>::None,
                consumed_prefix_digest,
            ],
        )?;
        for (username, (upload, download)) in &increments {
            transaction.execute(
                "INSERT INTO traffic_counters(username,upload_bytes,download_bytes,period_start,updated_at) \
                 VALUES(?,?,?,?,?) ON CONFLICT(username) DO UPDATE SET \
                 upload_bytes=upload_bytes+excluded.upload_bytes,\
                 download_bytes=download_bytes+excluded.download_bytes,updated_at=excluded.updated_at",
                params![username, *upload as i64, *download as i64, now, now],
            )?;
        }
        transaction.commit()?;
        self.secure_database_files()?;
        Ok((accepted, data.len() as u64, offset))
    }

    fn prune_consumed_deleted(&self, db: &Connection) -> Result<()> {
        let present = self.present_identities()?;
        let mut loss_detected = false;
        let rows: Vec<(i64, i64, i64, Option<i64>, i64)> = {
            let mut statement = db.prepare("SELECT device,inode,offset,file_size,discarding FROM traffic_files")?;
            let rows =
                statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let transaction = db.unchecked_transaction()?;
        for (device, inode, offset, size, discarding) in rows {
            if present.contains(&(device as u64, inode as u64)) {
                continue;
            }
            let safely_consumed = size.is_some_and(|size| offset == size) && discarding == 0;
            if !safely_consumed {
                loss_detected = true;
                transaction.execute(
                    "INSERT INTO accounting_state(singleton,error,detected_at) VALUES(1,?,?) \
                     ON CONFLICT(singleton) DO NOTHING",
                    params!["accounting_loss", now_iso()],
                )?;
            }
            transaction.execute("DELETE FROM traffic_files WHERE device=? AND inode=?", params![device, inode])?;
        }
        transaction.commit()?;
        if loss_detected {
            return Err(runtime("persistent accounting loss detected"));
        }
        Ok(())
    }

    /// One access-log line: a completed (2xx) CONNECT of a managed user with exact counters.
    pub fn parse(&self, raw: &[u8], users: &HashSet<String>) -> Option<(String, i64, i64)> {
        if raw.is_empty() || raw.len() as u64 > self.options.max_line_bytes {
            return None;
        }
        // `json.loads(bytes)` decodes UTF-8 with a byte-order mark too.
        let raw = raw.strip_prefix(b"\xef\xbb\xbf").unwrap_or(raw);
        let value: Value = serde_json::from_slice(raw).ok()?;
        let object = value.as_object()?;
        for key in ["request", "status", "user_id", "bytes_read", "size"] {
            object.get(key)?;
        }
        let int = |value: &Value| -> Option<i128> {
            match value {
                Value::Number(n) => n.as_i64().map(i128::from).or_else(|| n.as_u64().map(i128::from)),
                _ => None,
            }
        };
        let method = object["request"].as_object()?.get("method");
        let status = int(&object["status"])?;
        let username = object["user_id"].as_str()?;
        let upload = int(&object["bytes_read"])?;
        let download = int(&object["size"])?;
        let max = MAX_COUNTER as i128;
        if method != Some(&Value::String("CONNECT".into()))
            || !(200..300).contains(&status)
            || !users.contains(username)
            || username == REDACTION_SENTINEL
            || !(0..=max).contains(&upload)
            || !(0..=max).contains(&download)
            || upload > max - download
        {
            return None;
        }
        Some((username.to_string(), upload as i64, download as i64))
    }

    fn pending(&self, db: &Connection) -> Result<bool> {
        let candidates = match self.candidates() {
            Ok(candidates) => candidates,
            Err(Error::Os(_)) | Err(Error::Runtime(_)) => return Ok(true),
            Err(err) => return Err(err),
        };
        for candidate in candidates {
            let (_file, info) = match open_regular(&candidate.path) {
                Ok(opened) => opened,
                Err(Error::Os(_)) | Err(Error::Runtime(_)) => return Ok(true),
                Err(err) => return Err(err),
            };
            let identity = (info.dev(), info.ino());
            if identity != candidate.identity {
                return Ok(true);
            }
            let row: Option<i64> = db
                .query_row(
                    "SELECT offset FROM traffic_files WHERE device=? AND inode=?",
                    params![as_i64(identity.0)?, as_i64(identity.1)?],
                    |row| row.get(0),
                )
                .optional()?;
            let offset = row.map(|o| (o.max(0) as u64).min(info.len())).unwrap_or(0);
            if info.len() > offset {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn drain(&self) -> Result<bool> {
        for _ in 0..self.options.max_drain_rounds {
            self.collect()?;
            let guard = self.database();
            if !self.pending(guard.as_ref().ok_or_else(closed)?)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn list_traffic(&self) -> Result<Value> {
        let guard = self.database();
        let db = guard.as_ref().ok_or_else(closed)?;
        Self::assert_accounting_ready(db)?;
        let rows: Vec<(String, i64, i64, String, String)> = {
            let mut statement = db.prepare(
                "SELECT username,upload_bytes,download_bytes,period_start,updated_at FROM traffic_counters ORDER BY username",
            )?;
            let rows =
                statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let (mut upload_sum, mut download_sum, mut total_sum) = (0i128, 0i128, 0i128);
        let mut users = Vec::new();
        for (username, upload, download, period_start, updated_at) in rows {
            let total = upload as i128 + download as i128;
            upload_sum += upload as i128;
            download_sum += download as i128;
            total_sum += total;
            users.push(json!({
                "username": username,
                "upload_bytes": upload,
                "download_bytes": download,
                "total_bytes": number(total),
                "upload_bytes_decimal": upload.to_string(),
                "download_bytes_decimal": download.to_string(),
                "total_bytes_decimal": total.to_string(),
                "period_start": period_start,
                "updated_at": updated_at,
            }));
        }
        if total_sum > MAX_COUNTER as i128 {
            return Err(runtime("accounting counter invariant violated"));
        }
        let pending = self.pending(db)?;
        Ok(json!({
            "source": "caddy_connect_access_log",
            "unit": "bytes",
            "directions": {"upload_bytes": "client_to_proxy", "download_bytes": "proxy_to_client"},
            "aggregate": {
                "upload_bytes": number(upload_sum),
                "download_bytes": number(download_sum),
                "total_bytes": number(total_sum),
                "upload_bytes_decimal": upload_sum.to_string(),
                "download_bytes_decimal": download_sum.to_string(),
                "total_bytes_decimal": total_sum.to_string(),
            },
            "users": users,
            "pending": pending,
            "semantics": {
                "closed_connect_tunnels_only": true,
                "active_tunnels_appear_on_close": true,
                "crash_can_lose_active_tunnel": true,
                "completed_records_survive_restart": true,
                "excludes_tls_ip_overhead": true,
                "reset_is_local_baseline_only": true,
            },
        }))
    }

    pub fn archive_user(&self, username: &str) -> Result<()> {
        let now = now_iso();
        {
            let _operation = self.operation();
            let guard = self.database();
            let db = guard.as_ref().ok_or_else(closed)?;
            let transaction = db.unchecked_transaction()?;
            Self::assert_accounting_ready(db)?;
            let row: Option<(i64, i64, String, String)> = transaction
                .query_row(
                    "SELECT upload_bytes,download_bytes,period_start,updated_at FROM traffic_counters WHERE username=?",
                    params![username],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            if let Some((upload, download, period_start, updated_at)) = row {
                transaction.execute(
                    "INSERT INTO traffic_archives(username,upload_bytes,download_bytes,period_start,\
                     updated_at,archived_at) VALUES(?,?,?,?,?,?) ON CONFLICT(username) DO NOTHING",
                    params![username, upload, download, period_start, updated_at, now],
                )?;
                transaction.execute("DELETE FROM traffic_counters WHERE username=?", params![username])?;
            }
            transaction.commit()?;
        }
        self.secure_database_files()
    }

    pub fn reset(&self, username: &str) -> Result<Value> {
        let now = now_iso();
        {
            let _operation = self.operation();
            let guard = self.database();
            let db = guard.as_ref().ok_or_else(closed)?;
            let transaction = db.unchecked_transaction()?;
            Self::assert_accounting_ready(db)?;
            let users = (self.managed_users)()?;
            if !users.contains(username) {
                return Err(Error::Key(format!("'{username}'")));
            }
            transaction.execute(
                "INSERT INTO traffic_counters(username,upload_bytes,download_bytes,period_start,updated_at) \
                 VALUES(?,0,0,?,?) ON CONFLICT(username) DO UPDATE SET \
                 upload_bytes=0,download_bytes=0,period_start=excluded.period_start,updated_at=excluded.updated_at",
                params![username, now, now],
            )?;
            transaction.commit()?;
        }
        Ok(json!({
            "username": username,
            "upload_bytes": 0,
            "download_bytes": 0,
            "total_bytes": 0,
            "upload_bytes_decimal": "0",
            "download_bytes_decimal": "0",
            "total_bytes_decimal": "0",
            "period_start": now,
            "updated_at": now,
        }))
    }

    pub fn health(&self) -> Result<Value> {
        let ready = {
            let guard = self.database();
            let db = guard.as_ref().ok_or_else(closed)?;
            match Self::assert_accounting_ready(db).and_then(|()| open_regular(&self.log_path).map(drop)) {
                Ok(()) => lock(&self.last_error).is_none(),
                Err(err) if err.is_runtime() => false,
                Err(err) => return Err(err),
            }
        };
        Ok(json!({"ready": ready, "source": "caddy_connect_access_log", "error": *lock(&self.last_error)}))
    }
}

fn closed() -> Error {
    Error::Other("Cannot operate on a closed database.".into())
}

/// An exact integer, `i64` where it fits (it always does below the counter invariant).
fn number(value: i128) -> Value {
    i64::try_from(value).map(Value::from).unwrap_or_else(|_| Value::from(value as f64))
}
