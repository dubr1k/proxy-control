//! The adapter registry (`planner.adapter_factories()`): every adapter the binary knows, built
//! from one [`AdapterContext`].
//!
//! **Integration point of the adapter packages (host WP5a–e).** Each package adds its module
//! here (`pub mod packages;`, `pub mod nginx;`, …) and one line to [`registry`]. Nothing else in
//! the crate changes: the engine executes exactly the actions its stored plan names, the CLI
//! composes plans from [`installer_core::planner::adapters_for`] over this registry, and an
//! adapter missing from it surfaces as `BLOCKED: adapter is unavailable: <name>` (exit 2), the
//! engine's text.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use installer_core::model::InstallerConfig;
use pc_host::runner::HostRunner;

use crate::adapter::Adapter;
use crate::error::Error;

/// The worked example of the crate documentation (tests only, never registered).
#[cfg(test)]
pub(crate) mod example;

pub mod three_xui;

/// What every adapter is constructed with.
#[derive(Clone)]
pub struct AdapterContext {
    /// The host root (`--root`, `/` in production); every host path an adapter touches is
    /// `pc_host::fs::root_path(&root, "/abs/path")`.
    pub root: PathBuf,
    /// The release tree this binary belongs to (`<tree>/installer/bin/linux-amd64/…`): compose
    /// files, `release/*.json` pins, `deploy/`, the manager sources the adapters copy.
    pub tree: PathBuf,
    /// The one command boundary (`SystemRunner` in production, `RecordingRunner` in tests).
    pub runner: Arc<dyn HostRunner>,
}

impl std::fmt::Debug for AdapterContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdapterContext").field("root", &self.root).field("tree", &self.tree).finish_non_exhaustive()
    }
}

/// Every known adapter, registered with the engine up front: `resume`, `repair` and `uninstall`
/// run without composing a plan, so every adapter a stored plan may name must be there.
pub fn registry(context: &AdapterContext) -> Vec<Arc<dyn Adapter>> {
    // Host WP5a–e: one line per adapter, e.g.
    //     adapters.push(Arc::new(packages::PackagesAdapter::new(context)));
    let _ = context;
    Vec::new()
}

/// `installer.adapters.mcp.mcp_handoff(root, config)`: the MCP address and bearer for the
/// root-only report handoff (`report` with `domains.mcp`). Host WP5b replaces the body.
pub fn mcp_handoff(context: &AdapterContext, config: &InstallerConfig) -> Result<BTreeMap<String, String>, Error> {
    let _ = (context, config);
    Err(Error::other("McpError", "the MCP adapter is not available in this build yet"))
}
