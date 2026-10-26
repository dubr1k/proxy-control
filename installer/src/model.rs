//! The installer configuration model (`installer/model.py`).
//!
//! **Placeholder owned by host WP3.** The [`Adapter`](crate::adapter::Adapter) trait names
//! `crate::model::InstallerConfig` in `plan`, so the path is frozen; WP3 replaces the content with
//! the typed model (`InstallerConfig` with its domains, profile, ports, …) and keeps
//! [`InstallerConfig::canonical_dict`], which the plan stores as `config`.

use serde_json::Value;

/// The parsed, validated installer configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct InstallerConfig {
    canonical: Value,
}

impl InstallerConfig {
    /// A configuration known only by its canonical dictionary (until WP3's model lands).
    pub fn from_canonical(canonical: Value) -> InstallerConfig {
        InstallerConfig { canonical }
    }

    /// `InstallerConfig.canonical_dict()`: what `InstallPlan.config` holds.
    pub fn canonical_dict(&self) -> Value {
        self.canonical.clone()
    }
}
