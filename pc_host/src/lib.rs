//! Shared host plumbing of the Proxy Control installer and version-agent (the Rust port of
//! the host side of `installer/` and `version_agent/`).
//!
//! | Module | What | Python it replaces |
//! |---|---|---|
//! | [`fs`] | durable writes, fsync discipline, rooted host paths, path identities | `installer/transaction.py:77-184`, `:1550-1592` |
//! | [`lock`] | the host operation lock (`flock`) | `installer/transaction.py:187-219` |
//! | [`json`] | `json.dumps` byte-exact writers and readers for journals and agent state | `_canonical_json`, `_pretty_json`, the agent's state writer |
//! | [`runner`] | the three command contracts, a recording fake, process-group kill with `/proc` proof | `installer/audit.py:CommandRunner`, `adapters/core.py:_DefaultCoreRunner` |
//! | [`archive`] | `PANEL_SYNC`, panel archive preflight, reviewed artifacts, safe tar/zip extraction, release identity | `version_agent/service.py:77-85, 945-986`, `installer/release.py`, `installer/cli.py:138-160` |
//! | [`net`] | HTTPS with per-hop redirect allow-list, size caps, timeouts | `version_agent/upstream.py:open_allowed, fetch_https` |
//! | [`envfile`] | systemd EnvironmentFile quoting, escapes and continuations without shell expansion | native host and service configuration |
//! | [`error`] | `TransactionError` and subclasses with their Python class names | `installer/transaction.py:56-74` |
//!
//! The crate is Linux-only (procfs, `*at` system calls). It has no async runtime and no
//! `serde_json/preserve_order`: every host JSON format is key-sorted.
//!
//! # Public API (frozen at the end of host WP1; the integrator owns changes)
//!
//! - `fs`: `sha256_hex`, `sha256_file`, `sha256_reader`, `uuid4_hex`, `token_hex::<N>`,
//!   `py_parent`, `fsync_directory`, `fsync_file`, `fsync_tree`, `ensure_parent`,
//!   `durable_mkdir(path, mode)`, `atomic_write(path, data, mode, owner)`,
//!   `durable_copy2(src, dst)`, `durable_symlink(target, path)`, `durable_remove(path,
//!   missing_ok)`, `root_path(root, absolute) -> Result<PathBuf, TxError>`,
//!   `assert_contained(root, path)`, `owned_path(root, raw) -> (key, PathBuf)`,
//!   `path_identity(path) -> PathIdentity { kind: PathKind, sha256 }` (`to_json()`).
//! - `lock`: `operation_lock(root) -> Result<OperationLock, TxError>` (RAII guard, `path()`),
//!   `LOCK_PATH`, `BUSY_MESSAGE`, `UNSAFE_LOCK_MESSAGE`.
//! - `json`: `canonical`, `canonical_digest`, `pretty2`, `pretty2_ascii`, `pretty2_ascii_nonl`,
//!   `dumps(value, &Options)`, `float_repr`, `loads`, `loads_strict`, `JsonError`.
//! - `error`: `TxError::{Transaction, AcceptedDigest, Ownership, OwnershipRecoveryFailed, Busy,
//!   Io}` with `python_class_name()`, `message()`, `is_busy()`; `os_error_class(&io::Error)`.
//! - `runner`: trait `HostRunner { bounded, run, capture, capture_checked }`; `SystemRunner`;
//!   `RecordingRunner` (+ `Call`, `CallKind`, `Reply`); limits `Bounded::{AUDIT, NGINX,
//!   CERTIFICATES, PACKAGES, FIREWALL, WARP, NGINX_DUMP}`, `Bounded::new`,
//!   `with_call_timeout`; `RunOptions { stdin_path, env, timeout, cancel }`, `CORE_TIMEOUT`;
//!   `Capture::{CORE, MCP, VERSION_AGENT}`; `QUERY_TIMEOUT`; results `BoundedOutput`,
//!   `RunOutput`; errors `BoundedError`, `RunError` (`stops_the_engine()`), `QueryError`;
//!   helpers `bounded_capture`, `bounded_json`, `is_in_band_failure`, `capture_text`,
//!   `capture_unavailable`, `validate_argv`, `wait_process_group_stopped`; interrupts
//!   `install_interrupt_handler`, `interrupt_flag`, `request_interrupt`, `interrupted`;
//!   `CLEANUP_UNCONFIRMED`.
//! - `archive`: `PANEL_SYNC`, `handoff_allows`, `RUST_MANAGERS`, `RUST_SHARED`,
//!   `PANEL_AGENT_DIR`, `PANEL_ARCHIVE_PREFIX`, `PROJECT_DIR`, `AGENT_ROOT`, `MAX_PANEL_TREE`;
//!   `PanelArchive::{open, members, read, extract_to}`, `extract_panel_archive`,
//!   `PanelMember`, `PanelArchiveError`; `ReleaseManifest::{from_bytes, external_artifact}`,
//!   `ArtifactPin`, `MemberPin`, `verify_artifact`, `validate_release_url`,
//!   `normalize_archive_path`, `resolve_symlink_target`, `require_sha256`, `ReleaseError`;
//!   `safe_extract_tar(archive, destination, &ArchiveManifest)`, `ArchiveManifest::new`,
//!   `ArchiveEntry::{file, directory, symlink}`, `safe_extract_zip(archive, destination,
//!   &[(name, MemberPin)], max_member_bytes)`, `safe_extract_zip_default`;
//!   `ReleaseIdentity::{read, from_bytes}` (+ `binaries`, `builder`), `verify_binaries`,
//!   `PublishedManifest::{from_bytes, describes}`, `identity::{IDENTITY_PATH,
//!   INSTALLER_BINARY, AGENT_BINARY}`.
//! - `net`: `HttpsClient::{new, upstream, get, request, download}`, `ClientOptions`, `Roots`,
//!   `Request`, `Redirects`, `Response`, `Head`, `NetError`, `check_host`, `UPSTREAM_HOSTS`,
//!   `AGENT_USER_AGENT`, `MAX_REDIRECTS`, `DEFAULT_TIMEOUT`.
//! - `url`: `split(url) -> SplitResult { scheme, netloc, path, query, fragment }` with
//!   `hostname()`, `username()`, `password()`; `join(base, reference)`.
//! - `pytext`: `py_repr`, `py_path_str`, `py_title`, `text_mode`, `tail_chars`, `head_chars`.
//! - `envfile`: `read(path) -> io::Result<BTreeMap<String, String>>` (missing files mean no overrides).
//! - crate root: `INSTALLER_PATH`, `constant_time_eq`, re-exports `TxError`, `operation_lock`,
//!   `OperationLock`.

pub mod archive;
pub mod envfile;
pub mod error;
pub mod fs;
pub mod json;
pub mod lock;
pub mod net;
pub mod pytext;
pub mod runner;
pub mod url;

#[cfg(test)]
mod testarchive;
#[cfg(test)]
mod testutil;

pub use error::TxError;
pub use lock::{operation_lock, OperationLock};

/// Host path of the installer journal directory.
pub const INSTALLER_PATH: &str = "/var/lib/proxy-control/installer";

/// Compares two secrets (digests) in time that depends only on their lengths
/// (`secrets.compare_digest`).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    #[test]
    fn constant_time_eq_compares_bytes() {
        assert!(super::constant_time_eq(b"abc", b"abc"));
        assert!(!super::constant_time_eq(b"abc", b"abd"));
        assert!(!super::constant_time_eq(b"abc", b"abcd"));
    }
}
