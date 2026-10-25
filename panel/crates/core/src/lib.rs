//! Foundation of the Proxy Control panel's Rust port (work package WP1).
//!
//! Everything here reproduces a behaviour of the Python panel (`panel/*.py`) that other parts of
//! the panel depend on bit for bit:
//!
//! - [`settings`] — the environment variables of `panel/settings.py`, with the same defaults,
//!   parsing (Python's `int()`/`float()`/`str.lower()`/`str.strip()`) and the start-up checks of
//!   `create_app`;
//! - [`db`] — the SQLite boundary of `panel/database.py`: one connection per unit of work,
//!   `foreign_keys=ON`, `temp_store=MEMORY`, a 10 s busy timeout, WAL switched on with a retry loop,
//!   `BEGIN IMMEDIATE` transactions and the implicit `BEGIN` before DML of Python's `sqlite3`;
//! - [`migrations`] — the 26 schema migrations with their exact SQL text and recorded checksums,
//!   the downgrade and checksum refusals, and the refusal of pre-runner (v0.1.0) databases;
//! - [`pyjson`] — byte-exact `json.dumps` (separators, `indent`, `sort_keys`, `ensure_ascii`, float
//!   `repr`) and pydantic's `model_dump_json` over [`serde_json::Value`] (insertion order kept);
//! - [`pytext`] — Python's text semantics: `str.split()`/`strip()`, `isprintable`, NFC/NFKC,
//!   code-point slicing, `repr`, `lower`, `int()`/`float()`, `urllib.parse` quoting and `urlsplit`,
//!   and `ipaddress` (CPython 3.13's special-purpose tables);
//! - [`errors`] — the machine error codes and the four error-body shapes the API answers with;
//! - [`clock`] — wall and monotonic time behind a trait, with the tests' fake clock;
//! - [`ids`] — `uuid4()`, `token_urlsafe()` and `token_hex()` as Python formats them.
//!
//! All database calls are synchronous: call them from `tokio::task::spawn_blocking` (or a dedicated
//! thread) and never hold a [`db::Conn`] across an `.await`.

pub mod clock;
pub mod db;
pub mod errors;
pub mod ids;
pub mod migrations;
pub mod pyjson;
pub mod pytext;
pub mod settings;

pub use rusqlite;
pub use serde_json;
